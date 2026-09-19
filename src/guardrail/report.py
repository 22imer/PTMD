"""Output governance — validate report, re-ask hữu hạn, fallback abstention (spec §3.6, §4.2).

Cổng kiểm output Lớp 5 gồm ba lớp độc lập, không lớp nào thay thế lớp khác:

1. **Structural validation** — JSON Schema Draft-07 ``schemas/final_report.schema.json``
   qua ``jsonschema``. Đây là validator được ghim của prototype: **Guardrails AI
   được hoãn có chủ ý** (không thêm dependency mới; xem ``docs``/báo cáo T08), và
   schema §4.2 do T00 hoàn thiện chính là contract mà Guardrails AI sẽ bọc lại sau.
2. **Reference validation** — mọi ``evidence_id`` trong report phải tồn tại trong
   kho evidence **cùng artifact**; tham chiếu treo là lỗi validation, không phải
   cảnh báo.
3. **Verdict constraint validation** — cột "Ràng buộc Verdict" của ô ma trận
   §3.5.1 được áp qua ``banned_verdicts``; verdict bị cấm là lỗi validation.
   Không bao giờ ép nhãn ``BENIGN`` — hết lượt re-ask thì fallback ``INCONCLUSIVE``.

Ngoài ra module áp các ràng buộc MUST của §4.2 mà JSON Schema không mã hoá được
(schema là source of truth nhưng không có ``if/then`` cho nhánh abstention):
``report_status=ABSTAINED_PARTIAL`` ⇒ ``verdict=INCONCLUSIVE``,
``threat_score``/``confidence`` là ``null``, và có ``abstention_metadata``.

Re-ask loop: tối đa :data:`MAX_RE_ASKS` lần sau lần sinh ban đầu (tổng ≤ 3 lần
sinh). Mỗi lần re-ask nhận **thông báo lỗi cụ thể** của lần trước, rồi hết lượt
thì :class:`ReAskController` trả fallback ``ABSTAINED_PARTIAL`` (hoặc raise
``AbstentionRequired`` nếu caller không cấp factory).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import NamedTuple

import jsonschema

from guardrail.contracts import ReportStatus, Verdict, StatusFlag

__all__ = [
    "MAX_RE_ASKS",
    "REPORT_SCHEMA_PATH",
    "AbstentionRequired",
    "AgentRequest",
    "FallbackContractError",
    "ReportOutcome",
    "ReportValidator",
    "ReAskController",
    "ValidationResult",
    "build_fallback_report",
    "collect_evidence_ids",
    "load_report_schema",
    "validate_final_report",
]

#: Schema §4.2 (source of truth của report).
REPORT_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "final_report.schema.json"
#: Số lần re-ask tối đa sau lần sinh ban đầu (spec §3.6).
MAX_RE_ASKS = 2

_ABSTAINED = str(ReportStatus.ABSTAINED_PARTIAL)
_INCONCLUSIVE = str(Verdict.INCONCLUSIVE)
_EVIDENCE_ID_KEY = "evidence_id"


class AbstentionRequired(RuntimeError):
    """Hết lượt re-ask mà không có fallback factory được cấp."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = list(errors)
        super().__init__("report không hợp lệ sau khi hết lượt re-ask: " + "; ".join(errors))


class FallbackContractError(RuntimeError):
    """Fallback abstention do factory trả về không hợp schema §4.2."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = list(errors)
        super().__init__("fallback abstention không hợp lệ: " + "; ".join(errors))


class ValidationResult(NamedTuple):
    """Kết quả validate: ``valid`` ⇔ ``errors`` rỗng."""

    valid: bool
    errors: list[str]


def load_report_schema(path: str | Path | None = None) -> dict[str, object]:
    """Nạp schema report Draft-07 từ ``schemas/`` (mặc định :data:`REPORT_SCHEMA_PATH`)."""
    return json.loads(Path(path or REPORT_SCHEMA_PATH).read_text(encoding="utf-8"))


def collect_evidence_ids(store: object) -> set[str]:
    """Chuẩn hoá kho evidence thành tập ``evidence_id``.

    Nhận iterable/mapping các ``EvidenceRecord``, hoặc iterable/mapping các chuỗi
    ``evidence_id``. Phần tử lạ bị bỏ qua (không suy diễn id từ nguồn khác).
    """
    ids: set[str] = set()
    if isinstance(store, Mapping):
        candidates: Iterable[object] = store.values()
    elif isinstance(store, (str, bytes)):
        candidates = [store]
    elif isinstance(store, Iterable):
        candidates = store
    else:
        return ids
    for item in candidates:
        if isinstance(item, str):
            ids.add(item)
        elif isinstance(item, Mapping):
            value = item.get(_EVIDENCE_ID_KEY)
            if isinstance(value, str):
                ids.add(value)
    return ids


def _iter_evidence_references(report: Mapping[str, object]) -> list[tuple[str, str]]:
    """Liệt kê ``(path, evidence_id)`` của mọi khóa ``evidence_id`` trong report."""
    found: list[tuple[str, str]] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, Mapping):
            for key, value in node.items():
                child = f"{path}.{key}"
                if key == _EVIDENCE_ID_KEY and isinstance(value, str):
                    found.append((child, value))
                    continue
                walk(value, child)
        elif isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(report, "report")
    return found


def _schema_errors(report: object, schema: Mapping[str, object]) -> list[str]:
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(
        validator.iter_errors(report),
        key=lambda error: ([str(part) for part in error.absolute_path], error.message),
    )
    out: list[str] = []
    for error in errors:
        path = ".".join(str(part) for part in error.absolute_path)
        out.append(f"{'report.' + path if path else 'report'}: {error.message}")
    return out


def _abstention_errors(report: Mapping[str, object]) -> list[str]:
    """Ràng buộc MUST của §4.2 cho nhánh ``ABSTAINED_PARTIAL`` (schema không mã hoá)."""
    if report.get("report_status") != _ABSTAINED:
        return []
    errors: list[str] = []
    assessment = report.get("threat_assessment")
    verdict = assessment.get("verdict") if isinstance(assessment, Mapping) else None
    if verdict != _INCONCLUSIVE:
        errors.append(
            "report.threat_assessment.verdict: report_status=ABSTAINED_PARTIAL buộc "
            f"verdict='{_INCONCLUSIVE}', nhận {verdict!r} (§4.2)"
        )
    for field in ("threat_score", "confidence"):
        value = assessment.get(field) if isinstance(assessment, Mapping) else None
        if value is not None:
            errors.append(
                f"report.threat_assessment.{field}: report_status=ABSTAINED_PARTIAL buộc "
                f"null, nhận {value!r} (§4.2)"
            )
    if not isinstance(report.get("abstention_metadata"), Mapping):
        errors.append(
            "report.abstention_metadata: report_status=ABSTAINED_PARTIAL buộc kèm "
            "abstention_metadata{reason, validation_errors} (§4.2)"
        )
    return errors


def validate_final_report(
    report: object,
    *,
    evidence_store: object = (),
    banned_verdicts: Iterable[Verdict | str] = (),
    schema: Mapping[str, object] | None = None,
) -> ValidationResult:
    """Validate một report theo cả ba lớp (schema, tham chiếu evidence, ràng buộc verdict).

    Args:
        report: object ứng viên (thường là kết quả agent).
        evidence_store: kho evidence cùng artifact — nhận list ``EvidenceRecord``
            hoặc tập ``evidence_id``.
        banned_verdicts: cột "Ràng buộc Verdict" của ô ma trận đã tra.
        schema: schema tuỳ biến (mặc định nạp từ ``schemas/final_report.schema.json``).
    """
    active_schema = schema if schema is not None else load_report_schema()
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ValidationResult(
            valid=False,
            errors=[f"report: phải là object, nhận {type(report).__name__}"],
        )

    errors.extend(_schema_errors(report, active_schema))

    known = collect_evidence_ids(evidence_store)
    for path, evidence_id in _iter_evidence_references(report):
        if evidence_id not in known:
            errors.append(
                f"{path}: evidence_id '{evidence_id}' không tồn tại trong kho "
                "evidence của artifact (§3.6)"
            )

    banned = {str(verdict) for verdict in banned_verdicts}
    assessment = report.get("threat_assessment")
    verdict = assessment.get("verdict") if isinstance(assessment, Mapping) else None
    if isinstance(verdict, str) and verdict in banned:
        errors.append(
            "report.threat_assessment.verdict: verdict "
            f"'{verdict}' bị cấm bởi ô ma trận §3.5.1 tương ứng"
        )

    errors.extend(_abstention_errors(report))
    return ValidationResult(valid=not errors, errors=errors)


class ReportValidator:
    """Bọc :func:`validate_final_report` với schema/kho evidence/ràng buộc cố định."""

    def __init__(
        self,
        *,
        evidence_store: object = (),
        banned_verdicts: Iterable[Verdict | str] = (),
        schema: Mapping[str, object] | None = None,
    ) -> None:
        self.evidence_store = evidence_store
        self.banned_verdicts = tuple(banned_verdicts)
        self.schema = schema if schema is not None else load_report_schema()

    def validate(self, report: object) -> ValidationResult:
        return validate_final_report(
            report,
            evidence_store=self.evidence_store,
            banned_verdicts=self.banned_verdicts,
            schema=self.schema,
        )


class AgentRequest(NamedTuple):
    """Yêu cầu gửi cho agent (stub/thật) ở một lượt sinh report.

    ``attempt`` đếm từ 1; ``errors`` là thông báo lỗi cụ thể của lượt trước (rỗng
    ở lượt đầu) để agent sửa; ``tools`` là Dispatcher (nếu pipeline có cấp).
    """

    payload: Mapping[str, object] | None
    attempt: int
    errors: tuple[str, ...]
    tools: object | None = None


class ReportOutcome(NamedTuple):
    """Kết quả vòng generate/validate.

    - ``report``: report hợp lệ, hoặc fallback ``ABSTAINED_PARTIAL``.
    - ``attempts``: số lượt đã sinh (1 + số lần re-ask đã dùng).
    - ``errors``: lỗi của lượt cuối (rỗng khi ``report`` hợp lệ và không abstain).
    - ``abstained``: ``True`` khi phải dùng fallback abstention.
    """

    report: object
    attempts: int
    errors: list[str]
    abstained: bool


def build_fallback_report(
    *,
    artifact_sha256: str,
    file_type: str = "unknown",
    packer_detected: str = "unknown",
    reason: str,
    validation_errors: Sequence[str] = (),
    capabilities: Iterable[Mapping[str, object]] = (),
    status_flags: Sequence[StatusFlag | str] = (),
) -> dict[str, object]:
    """Dựng Fallback Abstention report hợp lệ §4.2 (spec §3.6).

    ``report_status=ABSTAINED_PARTIAL``, ``verdict=INCONCLUSIVE``,
    ``threat_score``/``confidence`` là ``null``, kèm
    ``abstention_metadata{reason, validation_errors}``. **Không** bao giờ ép
    ``BENIGN``: abstention là "không kết luận được", không phải "sạch".
    """
    if not reason:
        raise ValueError("reason phải là chuỗi khác rỗng")
    report: dict[str, object] = {
        "report_status": _ABSTAINED,
        "sample_metadata": {
            "sha256": artifact_sha256,
            "file_type": file_type,
            "packer_detected": packer_detected,
        },
        "threat_assessment": {
            "verdict": _INCONCLUSIVE,
            "threat_score": None,
            "confidence": None,
        },
        "mitre_attack_capabilities": [
            {
                "tactic": str(row.get("tactic", "")),
                "technique_id": str(row.get("technique_id", "")),
                "technique_name": str(row.get("technique_name", "")),
            }
            for row in capabilities
        ],
        "adversarial_evasion_findings": {
            "prompt_injection_detected": False,
            "evasion_attempts": [],
        },
        "executive_summary": (
            "Không thể hoàn tất báo cáo phân tích cho artifact này: pipeline abstain "
            f"({reason}). Kết luận bị treo ở mức INCONCLUSIVE thay vì suy diễn an toàn."
        ),
        "recommended_actions": [
            "Chuyển artifact cho analyst người xem xét thủ công trước mọi quyết định.",
            "Kiểm tra coverage của các detector bắt buộc và chạy lại khi đủ tầng.",
        ],
        "abstention_metadata": {
            "reason": reason,
            "validation_errors": [str(error) for error in validation_errors],
        },
    }
    if status_flags:
        report["status_flags"] = [str(flag) for flag in status_flags]
    return report


class ReAskController:
    """Vòng generate ➔ validate ➔ re-ask (≤ ``max_re_asks``) ➔ fallback abstention."""

    def __init__(self, validator: ReportValidator, *, max_re_asks: int = MAX_RE_ASKS) -> None:
        if max_re_asks < 0:
            raise ValueError("max_re_asks phải >= 0")
        self.validator = validator
        self.max_re_asks = max_re_asks

    @property
    def max_attempts(self) -> int:
        """Tổng số lượt sinh tối đa = 1 lần đầu + số lần re-ask."""
        return 1 + self.max_re_asks

    def run(
        self,
        agent: Callable[[AgentRequest], object],
        *,
        payload: Mapping[str, object] | None = None,
        tools: object | None = None,
        fallback_factory: Callable[[list[str]], Mapping[str, object]] | None = None,
    ) -> ReportOutcome:
        """Sinh report với tối đa ``max_attempts`` lượt, re-ask kèm lỗi cụ thể.

        Hết lượt mà vẫn lỗi: có ``fallback_factory`` ⇒ trả fallback abstention
        (``abstained=True``); không có ⇒ raise :class:`AbstentionRequired`.

        Fallback được kiểm schema + tham chiếu evidence (không áp ràng buộc verdict,
        vì fallback luôn là ``INCONCLUSIVE`` còn ô FAILED cấm mọi verdict); sai ⇒
        :class:`FallbackContractError`.
        """
        errors: list[str] = []
        report: object = None
        attempts = 0
        for attempt in range(1, self.max_attempts + 1):
            attempts = attempt
            request = AgentRequest(
                payload=payload, attempt=attempt, errors=tuple(errors), tools=tools
            )
            report = agent(request)
            result = self.validator.validate(report)
            if result.valid:
                return ReportOutcome(
                    report=report, attempts=attempts, errors=[], abstained=False
                )
            errors = result.errors
        if fallback_factory is None:
            raise AbstentionRequired(errors)
        fallback = fallback_factory(list(errors))
        check = validate_final_report(
            fallback,
            evidence_store=self.validator.evidence_store,
            schema=self.validator.schema,
        )
        if not check.valid:
            raise FallbackContractError(check.errors)
        return ReportOutcome(
            report=fallback,
            attempts=attempts,
            errors=list(errors),
            abstained=True,
        )
