"""Execution Rails Lớp 5 — Read-Only Dispatcher, ingress filter, Canary Verifier (spec §3.6).

Ba cơ chế, tất cả đều không có đường bypass:

1. **Hardcoded Read-Only Dispatcher** — chỉ ba hàm truy vấn dữ liệu đã làm sạch:
   :func:`ReadOnlyDispatcher.get_pe_header_details`,
   :func:`ReadOnlyDispatcher.get_mitre_capabilities`,
   :func:`ReadOnlyDispatcher.get_adversarial_findings`. Mọi tool name khác bị
   chặn **trước** khi tra handler (không side effect) và sinh bản ghi
   ``HARD_BLOCK`` qua ``guardrail.evidence.build_dispatcher_block_evidence``.
2. **Context Ingress Filtering** — mọi kết quả tool đi qua :func:`ingress_filter`
   trước khi vào context. Read-only **không** đồng nghĩa đáng tin: giá trị được
   escape ký tự cấu trúc và soi marker đối kháng; kết quả trả về context là bản
   đã escape, không bao giờ là raw của store.
3. **Canary Token Verifier** — :class:`CanaryVerifier` so khớp canary đã cấp và
   marker chỉ thị hệ thống trong output cuối của agent; khi khớp thì tước nội
   dung rò rỉ, sinh bản ghi ``TAG_AS_EVIDENCE`` (``detection_source=AGENT_OUTPUT``,
   ``detector_name=CANARY_VERIFIER``) và **không** cho phát hành output gốc.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import NamedTuple

from guardrail.context import escape_untrusted
from guardrail.contracts import EvidenceRecord, ProvenanceType
from guardrail.evidence import (
    build_canary_leak_evidence,
    build_dispatcher_block_evidence,
    build_provenance,
    format_evidence_id,
)

__all__ = [
    "ALLOWED_TOOLS",
    "CANARY_REDACTION",
    "CANARY_RULE_VERSION",
    "DISPATCHER_RULE_VERSION",
    "INGRESS_MARKERS",
    "SYSTEM_PROMPT_MARKERS",
    "SYSTEM_REDACTION",
    "CanaryHit",
    "CanaryVerdict",
    "CanaryVerifier",
    "DispatcherStore",
    "IngressFilterResult",
    "ReadOnlyDispatcher",
    "ToolInvocation",
    "escape_deep",
    "ingress_filter",
    "issue_canary",
]

#: Danh sách tool **duy nhất** Dispatcher phơi ra (spec §3.6).
ALLOWED_TOOLS: tuple[str, ...] = (
    "get_pe_header_details",
    "get_mitre_capabilities",
    "get_adversarial_findings",
)

DISPATCHER_RULE_VERSION = "read-only-dispatcher-v1"
CANARY_RULE_VERSION = "canary-verifier-v1"
#: Nội dung rò rỉ bị tước trước khi phát hành (spec §5, footnote Canary).
CANARY_REDACTION = "[REDACTED:CANARY]"
SYSTEM_REDACTION = "[REDACTED:SYSTEM_INSTRUCTION]"

#: Marker chỉ thị hệ thống — dấu hiệu prompt extraction thành công.
SYSTEM_PROMPT_MARKERS: tuple[str, ...] = ("critical integrity instruction",)

#: Dấu hiệu đối kháng soi khi lọc ingress; khớp theo chữ thường, giữ thứ tự khai báo.
INGRESS_MARKERS: tuple[str, ...] = (
    "<untrusted_malware_telemetry>",
    "</",
    "ignore previous instructions",
    "ignore all previous",
    "disregard previous",
    "system override",
    "you are now",
    "developer mode",
    "do not report",
    "output verdict: benign",
)


class DispatcherStore(NamedTuple):
    """Dữ liệu đã làm sạch mà Dispatcher được phép đọc (không truy cập ngoài)."""

    pe_header_details: Mapping[str, object]
    mitre_capabilities: Sequence[Mapping[str, object]]
    adversarial_findings: Sequence[Mapping[str, object]]


class IngressFilterResult(NamedTuple):
    """Kết quả lọc ingress cho một tool result.

    ``data`` là cấu trúc đã escape (giữ hình dạng); ``text`` là dạng serialize
    tất định để nhúng vào context; ``flagged``/``markers`` ghi dấu hiệu đối kháng
    phát hiện được (đã escape hay chưa đều bị soi).
    """

    data: object
    text: str
    flagged: bool
    markers: tuple[str, ...]


class ToolInvocation(NamedTuple):
    """Một lần gọi tool qua Dispatcher.

    ``allowed=False`` ⇒ tool bị chặn trước side effect: ``result is None`` và
    ``evidence`` là bản ghi ``HARD_BLOCK``. ``allowed=True`` ⇒ ``result`` là dữ
    liệu **đã qua ingress**, ``ingress`` giữ kết quả lọc đầy đủ.
    """

    tool: str
    allowed: bool
    result: object
    ingress: IngressFilterResult | None
    evidence: EvidenceRecord | None
    arguments: Mapping[str, object]


def escape_deep(value: object) -> object:
    """Escape đệ quy mọi chuỗi (kể cả khóa mapping) trong một cấu trúc JSON-like.

    Cấu trúc được giữ nguyên; chỉ nội dung chuỗi bị escape ký tự cấu trúc markup.
    """
    if isinstance(value, str):
        return escape_untrusted(value)
    if isinstance(value, Mapping):
        return {
            (escape_untrusted(key) if isinstance(key, str) else key): escape_deep(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [escape_deep(item) for item in value]
    return value


def _raw_text(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=repr)


def ingress_filter(value: object) -> IngressFilterResult:
    """Lọc kết quả tool trước khi đưa vào context (spec §3.6).

    Mọi kết quả — kể cả từ store read-only — đều bị escape ký tự cấu trúc và soi
    marker đối kháng. ``text`` là JSON tất định (khóa sắp xếp) nên cùng dữ liệu
    cho cùng chuỗi byte.
    """
    raw = _raw_text(value)
    lowered = raw.lower()
    markers = tuple(marker for marker in INGRESS_MARKERS if marker in lowered)
    escaped = escape_deep(value)
    if isinstance(escaped, str):
        text = escaped
    else:
        text = json.dumps(escaped, ensure_ascii=False, sort_keys=True, indent=2, default=repr)
    return IngressFilterResult(
        data=escaped, text=text, flagged=bool(markers), markers=markers
    )


class ReadOnlyDispatcher:
    """Dispatcher chỉ đọc, hardcode đúng ba tool của spec §3.6.

    ``handlers`` cho phép thay handler của tool **đã được phép** (dùng khi store
    đến từ nguồn khác); mọi tên ngoài ``ALLOWED_TOOLS`` bị chặn ở cổng trước khi
    tra handler, nên handler đăng ký cho tên cấm không bao giờ được gọi.
    """

    ALLOWED_TOOLS = ALLOWED_TOOLS

    def __init__(
        self,
        store: DispatcherStore,
        *,
        artifact_sha256: str,
        year: int = 2026,
        first_evidence_sequence: int = 1,
        rule_or_model_version: str = DISPATCHER_RULE_VERSION,
        handlers: Mapping[str, Callable[[], object]] | None = None,
        confidence_score: float = 1.0,
    ) -> None:
        if first_evidence_sequence < 1:
            raise ValueError("first_evidence_sequence phải >= 1")
        self.store = store
        self.artifact_sha256 = artifact_sha256
        self.year = year
        self.rule_or_model_version = rule_or_model_version
        self.confidence_score = confidence_score
        self._sequence = first_evidence_sequence
        self._handlers: dict[str, Callable[[], object]] = {
            "get_pe_header_details": self.get_pe_header_details,
            "get_mitre_capabilities": self.get_mitre_capabilities,
            "get_adversarial_findings": self.get_adversarial_findings,
        }
        if handlers:
            self._handlers.update(handlers)
        self._evidence: list[EvidenceRecord] = []

    # --- Ba truy vấn read-only duy nhất -----------------------------------

    def get_pe_header_details(self) -> Mapping[str, object]:
        """Chi tiết PE header đã làm sạch từ store."""
        return self.store.pe_header_details

    def get_mitre_capabilities(self) -> Sequence[Mapping[str, object]]:
        """Capabilities ATT&CK đã chiếu allowlist từ store."""
        return self.store.mitre_capabilities

    def get_adversarial_findings(self) -> Sequence[Mapping[str, object]]:
        """Findings đối kháng đã tóm tắt từ store."""
        return self.store.adversarial_findings

    # --- Cổng dispatch -----------------------------------------------------

    def dispatch(self, tool_name: str, **arguments: object) -> ToolInvocation:
        """Gọi một tool; tên ngoài allowlist bị chặn trước mọi side effect."""
        if not isinstance(tool_name, str) or not tool_name:
            raise ValueError("tool_name phải là chuỗi khác rỗng")
        if tool_name not in ALLOWED_TOOLS:
            return self._block(tool_name, arguments)
        handler = self._handlers[tool_name]
        raw = handler()
        ingress = ingress_filter(raw)
        return ToolInvocation(
            tool=tool_name,
            allowed=True,
            result=ingress.data,
            ingress=ingress,
            evidence=None,
            arguments=dict(arguments),
        )

    def _block(self, tool_name: str, arguments: Mapping[str, object]) -> ToolInvocation:
        evidence_id = self._next_evidence_id()
        record = build_dispatcher_block_evidence(
            evidence_id=evidence_id,
            artifact_sha256=self.artifact_sha256,
            rule_or_model_version=self.rule_or_model_version,
            score=1.0,
            provenance=build_provenance(
                ProvenanceType.RUNTIME_TOOL_CALL, locator=f"tool_call:{tool_name}"
            ),
            interpretation_summary=(
                f"Dispatcher Lớp 5 chặn tool-call trái phép '{tool_name}' trước khi "
                "có side effect; chỉ ba truy vấn read-only của §3.6 được phép."
            ),
            confidence_score=self.confidence_score,
        )
        self._evidence.append(record)
        return ToolInvocation(
            tool=tool_name,
            allowed=False,
            result=None,
            ingress=None,
            evidence=record,
            arguments=dict(arguments),
        )

    def _next_evidence_id(self) -> str:
        evidence_id = format_evidence_id(self.year, self._sequence)
        self._sequence += 1
        return evidence_id

    @property
    def blocked_evidence(self) -> list[EvidenceRecord]:
        """Bản ghi ``HARD_BLOCK`` đã sinh, theo thứ tự gọi."""
        return list(self._evidence)

    # --- Đường đọc "bypass" cố ý không tồn tại -----------------------------

    def __getattr__(self, name: str) -> object:  # pragma: no cover - guard đường bypass
        if name.startswith("_"):
            raise AttributeError(name)
        raise AttributeError(
            f"ReadOnlyDispatcher không phơi '{name}'; chỉ {list(ALLOWED_TOOLS)} (spec §3.6)"
        )


def issue_canary(label: str, *, prefix: str = "CANARY") -> str:
    """Cấp một token canary tất định từ nhãn (không dùng secret thật, không RNG).

    Cùng nhãn ⇒ cùng token; khác nhãn ⇒ khác token. Dùng cho test/smoke thay vì
    nhúng secret thật vào fixture.
    """
    if not isinstance(label, str) or not label:
        raise ValueError("label phải là chuỗi khác rỗng")
    digest = hashlib.sha256(label.encode("utf-8")).hexdigest()[:16].upper()
    return f"{prefix}-{label}-{digest}"


class CanaryHit(NamedTuple):
    """Một vị trí output khớp canary hoặc marker chỉ thị hệ thống."""

    token: str
    locator: str
    kind: str  # "CANARY" | "SYSTEM_MARKER"


class CanaryVerdict(NamedTuple):
    """Kết quả Canary Token Verifier.

    ``leaked=True`` ⇒ output gốc **không** được phát hành (``released=False``);
    ``output`` là bản đã tước nội dung rò rỉ và ``evidence`` là các bản ghi
    ``TAG_AS_EVIDENCE`` tương ứng (không chứa token).
    """

    leaked: bool
    released: bool
    output: object
    hits: tuple[CanaryHit, ...]
    evidence: tuple[EvidenceRecord, ...]


def _unique_mapping_key(existing: Mapping[object, object], key: str) -> str:
    """Khóa thay thế tất định khi khóa đã tước trùng khóa đã có trong kết quả.

    Hai khóa nguồn khác nhau (ví dụ chính token canary và chuỗi
    ``[REDACTED:CANARY]``) có thể cùng tước về một chuỗi. Ghi đè khi đó sẽ **âm
    thầm mất dữ liệu**, nên khóa đến sau nhận hậu tố ``#n`` tất định theo thứ tự
    chèn thay vì bị bỏ. Bản ghi rò rỉ vẫn được sinh (``leaked=True``) nên hành vi
    an toàn không đổi.
    """
    if key not in existing:
        return key
    index = 2
    while f"{key}#{index}" in existing:
        index += 1
    return f"{key}#{index}"


class CanaryVerifier:
    """So khớp canary đã cấp + marker chỉ thị hệ thống trong output cuối (§3.6, §5)."""

    def __init__(
        self,
        canaries: Iterable[str] = (),
        *,
        artifact_sha256: str,
        year: int = 2026,
        first_evidence_sequence: int = 1,
        rule_or_model_version: str = CANARY_RULE_VERSION,
        system_markers: Iterable[str] = SYSTEM_PROMPT_MARKERS,
        confidence_score: float = 1.0,
    ) -> None:
        tokens: list[str] = []
        for token in canaries:
            if not isinstance(token, str) or not token:
                raise ValueError("canary phải là chuỗi khác rỗng")
            if token not in tokens:
                tokens.append(token)
        self.canaries = tuple(tokens)
        markers: list[str] = []
        for marker in system_markers:
            if not isinstance(marker, str) or not marker.strip():
                raise ValueError("system_marker phải là chuỗi khác rỗng")
            lowered = marker.lower()
            if lowered not in markers:
                markers.append(lowered)
        self.system_markers = tuple(markers)
        self.artifact_sha256 = artifact_sha256
        self.year = year
        self.rule_or_model_version = rule_or_model_version
        self.confidence_score = confidence_score
        self._sequence = first_evidence_sequence
        self._evidence: list[EvidenceRecord] = []

    def verify(self, output: object) -> CanaryVerdict:
        """Quét output; tước nội dung rò rỉ và sinh bản ghi khi phát hiện.

        ``output`` nhận ``str`` (đầu ra thô) hoặc cấu trúc JSON-like của report.
        """
        if not isinstance(output, (str, Mapping, Sequence)) or isinstance(output, (bytes, bytearray)):
            raise TypeError(f"output phải là str hoặc cấu trúc JSON-like, nhận {type(output).__name__}")
        prefix = "agent_output" if isinstance(output, str) else "report"
        found: list[CanaryHit] = []
        sanitized = self._sanitize(output, prefix, found)

        unique: dict[tuple[str, str, str], CanaryHit] = {}
        for hit in found:
            unique.setdefault((hit.kind, hit.locator, hit.token), hit)
        hits = tuple(sorted(unique.values(), key=lambda item: (item.locator, item.kind, item.token)))

        records = tuple(self._record(hit) for hit in hits)
        self._evidence.extend(records)
        leaked = bool(hits)
        return CanaryVerdict(
            leaked=leaked,
            released=not leaked,
            output=sanitized,
            hits=hits,
            evidence=records,
        )

    @property
    def evidence(self) -> list[EvidenceRecord]:
        return list(self._evidence)

    # --- Nội bộ ------------------------------------------------------------

    def _sanitize(self, node: object, locator: str, found: list[CanaryHit]) -> object:
        """Tước rò rỉ đệ quy; khóa mapping được tước **đối xứng** với giá trị.

        Khóa ``str`` đi qua đúng đường :meth:`_sanitize_text` như giá trị (nên
        canary không thể tồn tại dai dẳng dưới dạng khóa); khóa không phải ``str``
        giữ nguyên. Nếu hai khóa khác nhau bị tước về cùng một chuỗi, khóa sau
        nhận hậu tố ``#n`` tất định (xem :func:`_unique_mapping_key`) để không
        khóa nào bị ghi đè âm thầm — lượt verify vẫn báo ``leaked=True`` nên
        không có đường phát hành bản gốc.
        """
        if isinstance(node, str):
            return self._sanitize_text(node, locator, found)
        if isinstance(node, Mapping):
            result: dict[object, object] = {}
            for key, value in node.items():
                if not isinstance(key, str):
                    result[key] = self._sanitize(value, f"{locator}.{key}", found)
                    continue
                key_hits: list[CanaryHit] = []
                sanitized_key = self._sanitize_text(key, locator, key_hits)
                stored_key = _unique_mapping_key(result, sanitized_key)
                entry_locator = f"{locator}.{stored_key}"
                found.extend(hit._replace(locator=entry_locator) for hit in key_hits)
                result[stored_key] = self._sanitize(value, entry_locator, found)
            return result
        if isinstance(node, (list, tuple)):
            return [
                self._sanitize(value, f"{locator}[{index}]", found)
                for index, value in enumerate(node)
            ]
        return node

    def _sanitize_text(self, text: str, locator: str, found: list[CanaryHit]) -> str:
        result = text
        for token in self.canaries:
            if token in result:
                found.append(CanaryHit(token=token, locator=locator, kind="CANARY"))
                result = result.replace(token, CANARY_REDACTION)
        lowered = result.lower()
        for marker in self.system_markers:
            if marker in lowered:
                found.append(
                    CanaryHit(token=marker, locator=locator, kind="SYSTEM_MARKER")
                )
                result = _replace_case_insensitive(result, marker, SYSTEM_REDACTION)
                lowered = result.lower()
        return result

    def _record(self, hit: CanaryHit) -> EvidenceRecord:
        evidence_id = format_evidence_id(self.year, self._sequence)
        self._sequence += 1
        if hit.kind == "CANARY":
            summary = (
                f"Output agent chứa canary đã cấp tại {hit.locator}; nội dung rò rỉ đã "
                "bị tước trước khi phát hành."
            )
            owasp = "LLM07:2025-SystemPromptLeakage"
        else:
            summary = (
                f"Output agent chứa marker chỉ thị hệ thống tại {hit.locator}; nội dung "
                "rò rỉ đã bị tước trước khi phát hành."
            )
            owasp = "LLM07:2025-SystemPromptLeakage"
        return build_canary_leak_evidence(
            evidence_id=evidence_id,
            artifact_sha256=self.artifact_sha256,
            rule_or_model_version=self.rule_or_model_version,
            score=1.0,
            provenance=build_provenance(
                ProvenanceType.AGENT_OUTPUT, locator=hit.locator
            ),
            interpretation_summary=summary,
            confidence_score=self.confidence_score,
            owasp_llm_mapping=owasp,
        )


def _replace_case_insensitive(text: str, needle: str, replacement: str) -> str:
    """Thay mọi lần xuất hiện không phân biệt hoa/thường mà không dùng regex động.

    ``needle`` rỗng trả về ``text`` nguyên trạng (kim rỗng khớp vô hạn vị trí).
    """
    if not needle:
        return text
    lowered = text.lower()
    result: list[str] = []
    cursor = 0
    while True:
        index = lowered.find(needle, cursor)
        if index == -1:
            result.append(text[cursor:])
            break
        result.append(text[cursor:index])
        result.append(replacement)
        cursor = index + len(needle)
    return "".join(result)
