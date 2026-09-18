"""Sinh bản ghi Quarantined Evidence cho Decision Policy Gate (spec v1.4.0 §3.5.1, §4.1, §5).

Module này là phần evidence của Lớp 4: biến quyết định policy thành danh sách bản
ghi `QuarantinedAdversarialEvidence` hợp lệ theo `schemas/quarantined_evidence.schema.json`.
Mọi hàm đều thuần, không I/O, không trạng thái: bản ghi dựng hoàn toàn từ tham
số truyền vào, `evidence_id` sinh tuần tự từ `(year, first_sequence)` do caller
cấp nên kết quả tất định và không cần bộ đếm nội bộ.

Ánh xạ action ➔ bản ghi (§3.5.1, "Ánh xạ Pipeline Action ➔ Evidence Decision"):

- `ALLOW` ➔ không bản ghi.
- `TAG_AS_EVIDENCE` ➔ `TAG_AS_EVIDENCE`.
- `CAUTIOUS_QUARANTINE` ➔ đúng hai bản ghi: `SANITIZE_AND_STRIP` (lưu trữ) rồi
  `ESCALATE_TO_HUMAN` (hàng đợi P2).
- `ESCALATE_AND_INCONCLUSIVE` ➔ `TAG_AS_EVIDENCE` cho từng finding rồi
  `ESCALATE_TO_HUMAN` cho coverage gap.
- `PIPELINE_ABSTENTION` ➔ `ESCALATE_TO_HUMAN` kèm tham chiếu raw telemetry (raw
  chỉ nằm ở kho điều tra, không đẩy vào context), sau đó `TAG_AS_EVIDENCE` cho
  từng finding đã phát hiện trước lỗi (Finding Preservation Rule, hàng 4 và 7).

`HARD_BLOCK` không có ô nào trong ma trận: nó do Dispatcher Lớp 5 và Canary
Verifier phát hành qua hai builder chuyên biệt, nơi các trường nhận dạng
(`detection_source`, `detector_name`, `policy_decision`, `pipeline_action`) bị
ghim cứng để không thể dán nhãn sai (§3.5.1, §5).

Builder tự kiểm các ràng buộc mà schema mã hoá (pattern `evidence_id`/`sha256`,
enum, `minItems: 1`, khoảng `score`/`confidence_score`, sentinel no-mapping ATLAS,
ràng buộc `VIRTUAL_ADDRESS`) và `raise EvidenceContractError` khi vi phạm, nên
bản ghi rời module này luôn qua được JSON Schema Draft-07. Phần kiểm schema thật
vẫn thuộc test (`jsonschema` chỉ là phụ thuộc test, không dùng ở runtime).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import NotRequired, TypedDict

from guardrail.contracts import (
    DetectionMethod,
    DetectionSource,
    DetectorName,
    EvidenceRecord,
    MitreAtlasMapping,
    OwaspLlmMapping,
    PipelineAction,
    PolicyDecision,
    Provenance,
    ProvenanceType,
    StatusFlag,
)
from guardrail.policy import DecisionOutcome, PolicyAction, to_pipeline_action

__all__ = [
    "EvidenceContractError",
    "EvidenceSeed",
    "Finding",
    "NO_MAPPING_REASON_DEFAULT",
    "NO_MAPPING_TECHNIQUE",
    "build_canary_leak_evidence",
    "build_dispatcher_block_evidence",
    "build_evidence_record",
    "build_finding_evidence",
    "build_provenance",
    "emit_policy_evidence",
    "format_evidence_id",
]


EVIDENCE_ID_PATTERN = re.compile(r"^EVD-[0-9]{4}-[0-9]{4,}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
VIRTUAL_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")

#: Sentinel no-mapping ATLAS (§4.1): `technique_id` = `technique_name`.
NO_MAPPING_TECHNIQUE = "No direct mapping"
#: Lý do mặc định cho sentinel no-mapping; caller có thể ghi đè bằng lý do cụ thể.
NO_MAPPING_REASON_DEFAULT = (
    "Không đủ bằng chứng hành vi quan sát được để ánh xạ MITRE ATLAS cho bản ghi này"
)

#: Hàng "Tool Execution Manipulation" của §5 — Dispatcher Lớp 5 chặn gọi tool.
_DISPATCHER_ATLAS: tuple[MitreAtlasMapping, ...] = (
    MitreAtlasMapping(technique_id="AML.T0053", technique_name="AI Agent Tool Invocation"),
)
#: Hàng "System Prompt Extraction Attempt" của §5 — Canary Token Verifier.
_CANARY_ATLAS: tuple[MitreAtlasMapping, ...] = (
    MitreAtlasMapping(technique_id="AML.T0056", technique_name="Extract LLM System Prompt"),
)

_DETECTION_SOURCES = frozenset(str(member) for member in DetectionSource)
_DETECTOR_NAMES = frozenset(str(member) for member in DetectorName)
_POLICY_DECISIONS = frozenset(str(member) for member in PolicyDecision)
_PIPELINE_ACTIONS = frozenset(str(member) for member in PipelineAction)
_PROVENANCE_TYPES = frozenset(str(member) for member in ProvenanceType)
_STATUS_FLAGS = frozenset(str(member) for member in StatusFlag)
_OWASP_MAPPINGS = frozenset(str(member) for member in OwaspLlmMapping)


class EvidenceContractError(ValueError):
    """Tham số dựng bản ghi vi phạm contract §4.1 hoặc §3.5.1."""


class Finding(TypedDict, total=False):
    """Một dương tính cần bảo toàn thành bản ghi `TAG_AS_EVIDENCE`.

    ``detector_name``, ``rule_or_model_version``, ``score``, ``detection_source``
    và ``provenance`` là bắt buộc; phần còn lại có mặc định an toàn (sentinel
    no-mapping ATLAS, `No direct mapping` cho OWASP, chuỗi biến đổi rỗng,
    `confidence_score` lấy theo điểm detector).
    """

    detector_name: str
    rule_or_model_version: str
    score: float
    detection_source: str
    provenance: Provenance
    interpretation_summary: str
    transform_chain: list[str]
    mitre_atlas_mappings: list[MitreAtlasMapping]
    no_mapping_reason: str
    owasp_llm_mapping: str
    confidence_score: NotRequired[float]


class EvidenceSeed(TypedDict, total=False):
    """Phần dùng chung để dựng một bản ghi không gắn với một finding đơn lẻ.

    Dùng cho bản ghi coverage gap / quarantine / abstention: ``detection_methods``,
    ``detection_source`` và ``provenance`` là bắt buộc; các trường còn lại có cùng
    mặc định như :class:`Finding`.
    """

    detection_methods: list[DetectionMethod]
    detection_source: str
    provenance: Provenance
    interpretation_summary: str
    transform_chain: list[str]
    mitre_atlas_mappings: list[MitreAtlasMapping]
    no_mapping_reason: str
    owasp_llm_mapping: str
    confidence_score: NotRequired[float]


# --- Tiện ích kiểm tra ----------------------------------------------------


def _require_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceContractError(f"'{field}' phải là chuỗi khác rỗng, nhận {value!r}")
    return value


def _require_enum(value: object, field: str, allowed: frozenset[str]) -> str:
    text = str(value)
    if text not in allowed:
        raise EvidenceContractError(
            f"'{field}' không thuộc vocabulary §4.1: {text!r} (cho phép: {sorted(allowed)})"
        )
    return text


def _require_score(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceContractError(f"'{field}' phải là số, nhận {value!r}")
    number = float(value)
    if not 0.0 <= number <= 1.0:
        raise EvidenceContractError(f"'{field}' phải trong [0.0, 1.0], nhận {number!r}")
    return number


def _optional_score(seed: dict[str, object], field: str) -> float | None:
    value = seed.get(field)
    if value is None:
        return None
    return _require_score(value, field)


# --- Dựng provenance ------------------------------------------------------


def build_provenance(
    kind: ProvenanceType | str,
    locator: str,
    *,
    section_or_pid: str | None = None,
    parent_artifact_sha256: str | None = None,
) -> Provenance:
    """Dựng `provenance` hợp lệ §4.1 (kèm ràng buộc `if/then` của `VIRTUAL_ADDRESS`).

    `VIRTUAL_ADDRESS` bắt buộc có `parent_artifact_sha256` và `locator` dạng
    `0x…`; các loại khác không được suy diễn thêm ràng buộc ngoài schema.
    """
    provenance: Provenance = {
        "type": _require_enum(kind, "provenance.type", _PROVENANCE_TYPES),
        "locator": _require_str(locator, "provenance.locator"),
        "section_or_pid": section_or_pid,
    }
    if parent_artifact_sha256 is not None:
        provenance["parent_artifact_sha256"] = _require_sha256(
            parent_artifact_sha256, "provenance.parent_artifact_sha256"
        )
    return _normalise_provenance(provenance)


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.match(value):
        raise EvidenceContractError(f"'{field}' phải là 64 ký tự hex, nhận {value!r}")
    return value


def _normalise_provenance(provenance: object) -> Provenance:
    if not isinstance(provenance, dict):
        raise EvidenceContractError("'provenance' phải là object")
    kind = _require_enum(provenance.get("type"), "provenance.type", _PROVENANCE_TYPES)
    locator = _require_str(provenance.get("locator"), "provenance.locator")
    if kind == ProvenanceType.VIRTUAL_ADDRESS:
        if "parent_artifact_sha256" not in provenance:
            raise EvidenceContractError(
                "provenance VIRTUAL_ADDRESS bắt buộc có 'parent_artifact_sha256' (§4.1)"
            )
        if not VIRTUAL_ADDRESS_PATTERN.match(locator):
            raise EvidenceContractError(
                f"provenance VIRTUAL_ADDRESS cần locator dạng '0x…', nhận {locator!r}"
            )
    out: Provenance = {"type": kind, "locator": locator}
    section = provenance.get("section_or_pid")
    if section is not None:
        if not isinstance(section, str):
            raise EvidenceContractError("'provenance.section_or_pid' phải là chuỗi hoặc null")
        out["section_or_pid"] = section
    elif "section_or_pid" in provenance:
        out["section_or_pid"] = None
    if "parent_artifact_sha256" in provenance:
        out["parent_artifact_sha256"] = _require_sha256(
            provenance["parent_artifact_sha256"], "provenance.parent_artifact_sha256"
        )
    return out


# --- Dựng các trường còn lại ----------------------------------------------


def format_evidence_id(year: int, sequence: int) -> str:
    """Sinh `evidence_id` theo pattern §4.1 `^EVD-[0-9]{4}-[0-9]{4,}$`.

    `sequence` là số thứ tự trong năm, bắt đầu từ 1; caller giữ bộ đếm (hàm thuần).
    """
    if isinstance(year, bool) or not isinstance(year, int) or not 0 <= year <= 9999:
        raise EvidenceContractError(f"'year' phải là số nguyên 0..9999, nhận {year!r}")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise EvidenceContractError(f"'sequence' phải là số nguyên >= 1, nhận {sequence!r}")
    return f"EVD-{year:04d}-{sequence:04d}"


def _normalise_methods(methods: object) -> list[DetectionMethod]:
    if not isinstance(methods, (list, tuple)) or not methods:
        raise EvidenceContractError("'detection_methods' cần ít nhất 1 phần tử (§4.1)")
    out: list[DetectionMethod] = []
    for index, method in enumerate(methods):
        if not isinstance(method, dict):
            raise EvidenceContractError(f"detection_methods[{index}] phải là object")
        out.append(
            DetectionMethod(
                detector_name=_require_enum(
                    method.get("detector_name"),
                    f"detection_methods[{index}].detector_name",
                    _DETECTOR_NAMES,
                ),
                rule_or_model_version=_require_str(
                    method.get("rule_or_model_version"),
                    f"detection_methods[{index}].rule_or_model_version",
                ),
                score=_require_score(method.get("score"), f"detection_methods[{index}].score"),
            )
        )
    return out


def _normalise_atlas(
    mappings: object, no_mapping_reason: object
) -> list[MitreAtlasMapping]:
    reason = (
        _require_str(no_mapping_reason, "no_mapping_reason")
        if no_mapping_reason is not None
        else NO_MAPPING_REASON_DEFAULT
    )
    if mappings is None or (isinstance(mappings, (list, tuple)) and not mappings):
        return [
            MitreAtlasMapping(
                technique_id=NO_MAPPING_TECHNIQUE,
                technique_name=NO_MAPPING_TECHNIQUE,
                no_mapping_reason=reason,
            )
        ]
    if not isinstance(mappings, (list, tuple)):
        raise EvidenceContractError("'mitre_atlas_mappings' phải là mảng")
    out: list[MitreAtlasMapping] = []
    for index, mapping in enumerate(mappings):
        if not isinstance(mapping, dict):
            raise EvidenceContractError(f"mitre_atlas_mappings[{index}] phải là object")
        technique_id = _require_str(
            mapping.get("technique_id"), f"mitre_atlas_mappings[{index}].technique_id"
        )
        technique_name = _require_str(
            mapping.get("technique_name"), f"mitre_atlas_mappings[{index}].technique_name"
        )
        entry: MitreAtlasMapping = {
            "technique_id": technique_id,
            "technique_name": technique_name,
        }
        if technique_id == NO_MAPPING_TECHNIQUE:
            if technique_name != NO_MAPPING_TECHNIQUE:
                raise EvidenceContractError(
                    "sentinel ATLAS cần technique_name = 'No direct mapping' (§4.1)"
                )
            entry["no_mapping_reason"] = (
                _require_str(mapping.get("no_mapping_reason"), f"mitre_atlas_mappings[{index}].no_mapping_reason")
                if mapping.get("no_mapping_reason") is not None
                else reason
            )
        elif mapping.get("no_mapping_reason") is not None:
            entry["no_mapping_reason"] = _require_str(
                mapping["no_mapping_reason"], f"mitre_atlas_mappings[{index}].no_mapping_reason"
            )
        out.append(entry)
    return out


def _normalise_transform_chain(chain: object) -> list[str]:
    if chain is None:
        return []
    if not isinstance(chain, (list, tuple)):
        raise EvidenceContractError("'transform_chain' phải là mảng chuỗi")
    out: list[str] = []
    for index, step in enumerate(chain):
        out.append(_require_str(step, f"transform_chain[{index}]"))
    return out


def _normalise_status_flags(flags: object) -> list[StatusFlag]:
    if flags is None:
        return []
    if not isinstance(flags, (list, tuple)):
        raise EvidenceContractError("'status_flags' phải là mảng")
    out: list[StatusFlag] = []
    for index, flag in enumerate(flags):
        value = StatusFlag(_require_enum(flag, f"status_flags[{index}]", _STATUS_FLAGS))
        if value in out:
            raise EvidenceContractError(f"'status_flags' bị trùng giá trị {value!r} (§4.1 uniqueItems)")
        out.append(value)
    return out


# --- Dựng bản ghi ---------------------------------------------------------


def build_evidence_record(
    seed: EvidenceSeed,
    *,
    evidence_id: str,
    artifact_sha256: str,
    policy_decision: PolicyDecision | str,
    pipeline_action: PipelineAction | str,
    status_flags: Sequence[StatusFlag | str] = (),
) -> EvidenceRecord:
    """Dựng một bản ghi `QuarantinedAdversarialEvidence` hợp lệ.

    Trường bắt buộc của seed: `detection_methods`, `detection_source`, `provenance`,
    `interpretation_summary`. `confidence_score` mặc định lấy điểm detector cao
    nhất (0.0 nếu không xác định); ATLAS thiếu mapping dùng sentinel no-mapping.
    Thứ tự trường theo ví dụ §4.3 để bản ghi đọc/serialize ổn định.
    """
    if not isinstance(seed, dict):
        raise EvidenceContractError("seed phải là object")
    methods = _normalise_methods(seed.get("detection_methods"))
    confidence = _optional_score(seed, "confidence_score")
    if confidence is None:
        confidence = max(method["score"] for method in methods)
    record: EvidenceRecord = {
        "evidence_id": _require_evidence_id(evidence_id),
        "artifact_sha256": _require_sha256(artifact_sha256, "artifact_sha256"),
        "provenance": _normalise_provenance(seed.get("provenance")),
        "detection_source": _require_enum(
            seed.get("detection_source"), "detection_source", _DETECTION_SOURCES
        ),
        "detection_methods": methods,
        "transform_chain": _normalise_transform_chain(seed.get("transform_chain")),
        "mitre_atlas_mappings": _normalise_atlas(
            seed.get("mitre_atlas_mappings"), seed.get("no_mapping_reason")
        ),
        "owasp_llm_mapping": _require_enum(
            seed.get("owasp_llm_mapping", OwaspLlmMapping.NO_DIRECT_MAPPING),
            "owasp_llm_mapping",
            _OWASP_MAPPINGS,
        ),
        "confidence_score": confidence,
        "policy_decision": _require_enum(
            policy_decision, "policy_decision", _POLICY_DECISIONS
        ),
        "pipeline_action": _require_enum(
            pipeline_action, "pipeline_action", _PIPELINE_ACTIONS
        ),
        "status_flags": _normalise_status_flags(status_flags),
        "interpretation_summary": _require_str(
            seed.get("interpretation_summary"), "interpretation_summary"
        ),
    }
    return record


def _require_evidence_id(value: object) -> str:
    if not isinstance(value, str) or not EVIDENCE_ID_PATTERN.match(value):
        raise EvidenceContractError(
            f"'evidence_id' phải khớp ^EVD-[0-9]{{4}}-[0-9]{{4,}}$, nhận {value!r}"
        )
    return value


def build_finding_evidence(
    finding: Finding,
    *,
    evidence_id: str,
    artifact_sha256: str,
    pipeline_action: PipelineAction | str,
    policy_decision: PolicyDecision | str = PolicyDecision.TAG_AS_EVIDENCE,
    status_flags: Sequence[StatusFlag | str] = (),
) -> EvidenceRecord:
    """Dựng bản ghi cho một finding dương tính (Finding Preservation Rule).

    `detection_methods` của bản ghi là đúng detector đã tạo ra finding đó, nên
    truy nguyên finding ➔ bản ghi ➔ artifact không đi qua suy diễn.
    """
    if not isinstance(finding, dict):
        raise EvidenceContractError("finding phải là object")
    seed = EvidenceSeed(
        detection_methods=[
            DetectionMethod(
                detector_name=_require_enum(
                    finding.get("detector_name"), "finding.detector_name", _DETECTOR_NAMES
                ),
                rule_or_model_version=_require_str(
                    finding.get("rule_or_model_version"), "finding.rule_or_model_version"
                ),
                score=_require_score(finding.get("score"), "finding.score"),
            )
        ],
        detection_source=finding.get("detection_source"),
        provenance=finding.get("provenance"),
        interpretation_summary=finding.get("interpretation_summary"),
        transform_chain=finding.get("transform_chain"),
        mitre_atlas_mappings=finding.get("mitre_atlas_mappings"),
        no_mapping_reason=finding.get("no_mapping_reason"),
        owasp_llm_mapping=finding.get("owasp_llm_mapping", OwaspLlmMapping.NO_DIRECT_MAPPING),
        confidence_score=finding.get("confidence_score"),
    )
    return build_evidence_record(
        seed,
        evidence_id=evidence_id,
        artifact_sha256=artifact_sha256,
        policy_decision=policy_decision,
        pipeline_action=pipeline_action,
        status_flags=status_flags,
    )


# --- Ánh xạ action ➔ bản ghi (spec §3.5.1) --------------------------------


def _coerce_action(action: PolicyAction | str) -> PolicyAction:
    try:
        return PolicyAction(str(action))
    except ValueError as exc:
        raise EvidenceContractError(
            f"emit_policy_evidence chỉ nhận action của ma trận §3.5.1, nhận {action!r}"
        ) from exc


def _require_seed(detection: EvidenceSeed | None, action: PolicyAction) -> EvidenceSeed:
    if detection is None:
        raise EvidenceContractError(
            f"{action} cần 'detection' (coverage gap / nội dung phát hiện) để phát hành bản ghi"
        )
    return detection


def emit_policy_evidence(
    outcome: DecisionOutcome,
    *,
    artifact_sha256: str,
    year: int,
    first_sequence: int,
    findings: Sequence[Finding] = (),
    detection: EvidenceSeed | None = None,
    raw_telemetry: Provenance | None = None,
) -> list[EvidenceRecord]:
    """Phát hành bản ghi evidence theo ánh xạ action của ma trận §3.5.1.

    `evidence_id` cấp tuần tự từ `(year, first_sequence)` theo đúng thứ tự bản ghi
    trả về. `detection` mang nội dung cho bản ghi không gắn finding đơn lẻ
    (quarantine, coverage gap, abstention); `raw_telemetry` là con trỏ tới raw
    telemetry trong kho điều tra — chỉ được ghi vào provenance của bản ghi
    abstention, không bao giờ là nội dung context. Khi `raw_telemetry` không được
    truyền, bản ghi abstention giữ provenance của `detection`.
    """
    action = _coerce_action(outcome.pipeline_action)
    pipeline_action = to_pipeline_action(action)
    if pipeline_action is None:
        return []

    records: list[EvidenceRecord] = []
    sequence = first_sequence

    def emit(seed: EvidenceSeed, decision: PolicyDecision) -> None:
        nonlocal sequence
        records.append(
            build_evidence_record(
                seed,
                evidence_id=format_evidence_id(year, sequence),
                artifact_sha256=artifact_sha256,
                policy_decision=decision,
                pipeline_action=pipeline_action,
                status_flags=outcome.status_flags,
            )
        )
        sequence += 1

    def emit_findings() -> None:
        nonlocal sequence
        for finding in findings:
            records.append(
                build_finding_evidence(
                    finding,
                    evidence_id=format_evidence_id(year, sequence),
                    artifact_sha256=artifact_sha256,
                    policy_decision=PolicyDecision.TAG_AS_EVIDENCE,
                    pipeline_action=pipeline_action,
                    status_flags=outcome.status_flags,
                )
            )
            sequence += 1

    if action is PolicyAction.TAG_AS_EVIDENCE:
        if findings:
            emit_findings()
        else:
            emit(_require_seed(detection, action), PolicyDecision.TAG_AS_EVIDENCE)
        return records

    if action is PolicyAction.CAUTIOUS_QUARANTINE:
        seed = _require_seed(detection, action)
        emit(seed, PolicyDecision.SANITIZE_AND_STRIP)
        emit(seed, PolicyDecision.ESCALATE_TO_HUMAN)
        return records

    if action is PolicyAction.ESCALATE_AND_INCONCLUSIVE:
        emit_findings()
        emit(_require_seed(detection, action), PolicyDecision.ESCALATE_TO_HUMAN)
        return records

    # PIPELINE_ABSTENTION: escalation coverage gap trước, rồi bảo toàn finding.
    seed = _require_seed(detection, action)
    if raw_telemetry is not None:
        seed = EvidenceSeed(seed, provenance=_normalise_provenance(raw_telemetry))
    emit(seed, PolicyDecision.ESCALATE_TO_HUMAN)
    emit_findings()
    return records


# --- Bản ghi Lớp 5 (Dispatcher & Canary) ----------------------------------


def build_dispatcher_block_evidence(
    *,
    evidence_id: str,
    artifact_sha256: str,
    rule_or_model_version: str,
    score: float,
    provenance: Provenance,
    interpretation_summary: str,
    confidence_score: float | None = None,
    transform_chain: Sequence[str] = (),
    mitre_atlas_mappings: Sequence[MitreAtlasMapping] | None = None,
    owasp_llm_mapping: OwaspLlmMapping | str = OwaspLlmMapping.EXCESSIVE_AGENCY,
) -> EvidenceRecord:
    """Bản ghi `HARD_BLOCK` khi Dispatcher Lớp 5 chặn tool-call trái phép (§3.5.1, §5).

    Ghim `detection_source = RUNTIME_TOOL_CALL`, `detector_name = READ_ONLY_DISPATCHER`,
    `policy_decision = pipeline_action = HARD_BLOCK` và bắt buộc provenance loại
    `RUNTIME_TOOL_CALL`. Ánh xạ mặc định theo hàng "Tool Execution Manipulation":
    ATLAS `AML.T0053`, OWASP `LLM06:2025-ExcessiveAgency`; không gán mã ATT&CK
    execution vì đây mới là attempted invocation.
    """
    if _require_enum(
        provenance.get("type") if isinstance(provenance, dict) else None,
        "provenance.type",
        _PROVENANCE_TYPES,
    ) != ProvenanceType.RUNTIME_TOOL_CALL:
        raise EvidenceContractError(
            "bản ghi HARD_BLOCK của dispatcher cần provenance.type = 'RUNTIME_TOOL_CALL' (§3.5.1)"
        )
    seed = EvidenceSeed(
        detection_methods=[
            DetectionMethod(
                detector_name=DetectorName.READ_ONLY_DISPATCHER,
                rule_or_model_version=_require_str(
                    rule_or_model_version, "rule_or_model_version"
                ),
                score=_require_score(score, "score"),
            )
        ],
        detection_source=DetectionSource.RUNTIME_TOOL_CALL,
        provenance=provenance,
        interpretation_summary=interpretation_summary,
        transform_chain=list(transform_chain),
        mitre_atlas_mappings=list(mitre_atlas_mappings) if mitre_atlas_mappings else list(_DISPATCHER_ATLAS),
        owasp_llm_mapping=owasp_llm_mapping,
        confidence_score=confidence_score,
    )
    return build_evidence_record(
        seed,
        evidence_id=evidence_id,
        artifact_sha256=artifact_sha256,
        policy_decision=PolicyDecision.HARD_BLOCK,
        pipeline_action=PipelineAction.HARD_BLOCK,
    )


def build_canary_leak_evidence(
    *,
    evidence_id: str,
    artifact_sha256: str,
    rule_or_model_version: str,
    score: float,
    provenance: Provenance,
    interpretation_summary: str,
    confidence_score: float | None = None,
    transform_chain: Sequence[str] = (),
    mitre_atlas_mappings: Sequence[MitreAtlasMapping] | None = None,
    owasp_llm_mapping: OwaspLlmMapping | str = OwaspLlmMapping.SYSTEM_PROMPT_LEAKAGE,
) -> EvidenceRecord:
    """Bản ghi `TAG_AS_EVIDENCE` khi Canary Token Verifier phát hiện rò rỉ (§3.5.1, §5).

    Ghim `detection_source = AGENT_OUTPUT`, `detector_name = CANARY_VERIFIER`,
    `policy_decision = pipeline_action = TAG_AS_EVIDENCE` và bắt buộc provenance
    loại `AGENT_OUTPUT`. Nội dung rò rỉ đã bị tước trước khi phát hành; bản ghi
    chỉ giữ vị trí và ngữ cảnh, không chứa canary.
    """
    if _require_enum(
        provenance.get("type") if isinstance(provenance, dict) else None,
        "provenance.type",
        _PROVENANCE_TYPES,
    ) != ProvenanceType.AGENT_OUTPUT:
        raise EvidenceContractError(
            "bản ghi canary leak cần provenance.type = 'AGENT_OUTPUT' (§3.5.1)"
        )
    seed = EvidenceSeed(
        detection_methods=[
            DetectionMethod(
                detector_name=DetectorName.CANARY_VERIFIER,
                rule_or_model_version=_require_str(
                    rule_or_model_version, "rule_or_model_version"
                ),
                score=_require_score(score, "score"),
            )
        ],
        detection_source=DetectionSource.AGENT_OUTPUT,
        provenance=provenance,
        interpretation_summary=interpretation_summary,
        transform_chain=list(transform_chain),
        mitre_atlas_mappings=list(mitre_atlas_mappings) if mitre_atlas_mappings else list(_CANARY_ATLAS),
        owasp_llm_mapping=owasp_llm_mapping,
        confidence_score=confidence_score,
    )
    return build_evidence_record(
        seed,
        evidence_id=evidence_id,
        artifact_sha256=artifact_sha256,
        policy_decision=PolicyDecision.TAG_AS_EVIDENCE,
        pipeline_action=PipelineAction.TAG_AS_EVIDENCE,
    )
