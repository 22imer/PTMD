"""Contract dữ liệu dùng chung cho guardrail (T01).

**Source of truth** là hai JSON Schema Draft-07 trong `schemas/`:

- `schemas/quarantined_evidence.schema.json` — spec v1.4.0 §4.1
  (`QuarantinedAdversarialEvidence`).
- `schemas/final_report.schema.json` — spec v1.4.0 §4.2
  (`MalwareAgentFinalReport`).

Các enum và record dưới đây phản chiếu đúng vocabulary của hai schema đó; không
thêm/bớt giá trị enum, không thêm ràng buộc ngoài spec. Khi schema đổi, đổi file
`schemas/` trước rồi cập nhật module này; `tests/test_contracts.py` chốt lại
tương quan hai chiều (schema khớp nguyên văn block trong spec, và record hợp
lệ/không hợp lệ theo đúng các ràng buộc schema mã hoá).

Ngoài hai schema, `ProcessingState` và `DetectionState` lấy từ ma trận quyết
định §3.5.1 và quy tắc tổng hợp detector §3.5.1.1 của spec v1.4.0: hai trục
trạng thái này độc lập nhau và không xuất hiện như trường trong bản ghi, nên
không tồn tại trong schema. `PipelineAction` giữ đúng 5 giá trị của enum
`pipeline_action` (§4.1); nhánh `ALLOW` của ma trận không sinh bản ghi evidence
nên không nằm trong enum này (§3.5.1, ánh xạ Pipeline Action ➔ Evidence
Decision).

TypedDict ở đây chỉ mô tả cấu trúc tĩnh để gọi API nội bộ; ràng buộc runtime
(`required`, `pattern`, `if/then`, `minItems`, `enum` của `status_flags`, quan hệ
report ➔ evidence) do JSON Schema hiện hành thực thi.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NotRequired, TypedDict

__all__ = [
    "DetectionMethod",
    "DetectionSource",
    "DetectionState",
    "DetectorName",
    "EvidenceRecord",
    "FinalReport",
    "MitreAtlasMapping",
    "MitreAttackCapability",
    "OwaspLlmMapping",
    "PipelineAction",
    "PolicyDecision",
    "ProcessingState",
    "Provenance",
    "ProvenanceType",
    "ReportStatus",
    "StatusFlag",
    "Verdict",
]


# --- Enum: trạng thái pipeline (spec §3.5.1, §3.5.1.1) ---------------------


class ProcessingState(StrEnum):
    """Trạng thái coverage của pipeline (cột Processing State, §3.5.1)."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class DetectionState(StrEnum):
    """Kết quả tổng hợp của các detector bắt buộc (§3.5.1.1)."""

    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


# --- Enum: vocabulary của schema §4.1 / §4.2 ------------------------------


class PipelineAction(StrEnum):
    """Enum `pipeline_action` (schema §4.1)."""

    TAG_AS_EVIDENCE = "TAG_AS_EVIDENCE"
    CAUTIOUS_QUARANTINE = "CAUTIOUS_QUARANTINE"
    ESCALATE_AND_INCONCLUSIVE = "ESCALATE_AND_INCONCLUSIVE"
    PIPELINE_ABSTENTION = "PIPELINE_ABSTENTION"
    HARD_BLOCK = "HARD_BLOCK"


class PolicyDecision(StrEnum):
    """Enum `policy_decision` (schema §4.1) — quyết định ở mức bản ghi."""

    TAG_AS_EVIDENCE = "TAG_AS_EVIDENCE"
    SANITIZE_AND_STRIP = "SANITIZE_AND_STRIP"
    HARD_BLOCK = "HARD_BLOCK"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"


class ProvenanceType(StrEnum):
    """Enum `provenance.type` (schema §4.1)."""

    FILE_OFFSET = "FILE_OFFSET"
    VIRTUAL_ADDRESS = "VIRTUAL_ADDRESS"
    JSON_LOG_POINTER = "JSON_LOG_POINTER"
    RUNTIME_TOOL_CALL = "RUNTIME_TOOL_CALL"
    AGENT_OUTPUT = "AGENT_OUTPUT"


class DetectionSource(StrEnum):
    """Enum `detection_source` (schema §4.1)."""

    STATIC_STRING = "STATIC_STRING"
    DYNAMIC_MEMORY_DUMP = "DYNAMIC_MEMORY_DUMP"
    SANDBOX_API_LOG = "SANDBOX_API_LOG"
    SANDBOX_NETWORK_TRACE = "SANDBOX_NETWORK_TRACE"
    RUNTIME_TOOL_CALL = "RUNTIME_TOOL_CALL"
    AGENT_OUTPUT = "AGENT_OUTPUT"


class DetectorName(StrEnum):
    """Enum `detector_name` (schema §4.1)."""

    YARA_STATIC = "YARA_STATIC"
    YARA_CUCKOO = "YARA_CUCKOO"
    META_PROMPT_GUARD = "META_PROMPT_GUARD"
    TELEMETRY_ADAPTER = "TELEMETRY_ADAPTER"
    READ_ONLY_DISPATCHER = "READ_ONLY_DISPATCHER"
    CANARY_VERIFIER = "CANARY_VERIFIER"


class StatusFlag(StrEnum):
    """Enum phần tử của `status_flags` (schema §4.1 và §4.2)."""

    DETECTOR_DISAGREEMENT = "DETECTOR_DISAGREEMENT"
    TRUNCATED_ARTIFACT_FLAG = "TRUNCATED_ARTIFACT_FLAG"


class OwaspLlmMapping(StrEnum):
    """Enum `owasp_llm_mapping` (schema §4.1)."""

    PROMPT_INJECTION = "LLM01:2025-PromptInjection"
    EXCESSIVE_AGENCY = "LLM06:2025-ExcessiveAgency"
    SYSTEM_PROMPT_LEAKAGE = "LLM07:2025-SystemPromptLeakage"
    NO_DIRECT_MAPPING = "No direct mapping"


class ReportStatus(StrEnum):
    """Enum `report_status` (schema §4.2)."""

    COMPLETE = "COMPLETE"
    ABSTAINED_PARTIAL = "ABSTAINED_PARTIAL"


class Verdict(StrEnum):
    """Enum `threat_assessment.verdict` (schema §4.2)."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    INCONCLUSIVE = "INCONCLUSIVE"


# --- Record: schema §4.1 --------------------------------------------------


class Provenance(TypedDict):
    """`provenance` (schema §4.1).

    Ràng buộc schema không biểu diễn được bằng TypedDict: khi `type` là
    `VIRTUAL_ADDRESS` thì `parent_artifact_sha256` bắt buộc và `locator` phải
    khớp `^0x[0-9a-fA-F]+$`.
    """

    type: ProvenanceType
    locator: str
    section_or_pid: NotRequired[str | None]
    parent_artifact_sha256: NotRequired[str]


class DetectionMethod(TypedDict):
    """Phần tử của `detection_methods` (schema §4.1)."""

    detector_name: DetectorName
    rule_or_model_version: str
    score: float


class MitreAtlasMapping(TypedDict):
    """Phần tử của `mitre_atlas_mappings` (schema §4.1).

    Sentinel no-mapping: `technique_id` = `technique_name` = `No direct mapping`
    và bắt buộc kèm `no_mapping_reason`.
    """

    technique_id: str
    technique_name: str
    no_mapping_reason: NotRequired[str]


class EvidenceRecord(TypedDict):
    """`QuarantinedAdversarialEvidence` (schema §4.1), cấu trúc top-level.

    `status_flags` là trường tuỳ hành (schema không đưa vào `required`).
    """

    evidence_id: str
    artifact_sha256: str
    provenance: Provenance
    detection_source: DetectionSource
    detection_methods: list[DetectionMethod]
    transform_chain: list[str]
    mitre_atlas_mappings: list[MitreAtlasMapping]
    owasp_llm_mapping: OwaspLlmMapping
    confidence_score: float
    policy_decision: PolicyDecision
    pipeline_action: PipelineAction
    interpretation_summary: str
    status_flags: NotRequired[list[StatusFlag]]


# --- Record: schema §4.2 --------------------------------------------------


class MitreAttackCapability(TypedDict):
    """Phần tử của `mitre_attack_capabilities` (schema §4.2)."""

    tactic: str
    technique_id: str
    technique_name: str


class FinalReport(TypedDict):
    """`MalwareAgentFinalReport` (schema §4.2), cấu trúc top-level.

    `abstention_metadata` và `status_flags` là trường tuỳ hành (schema không đưa
    vào `required`).
    """

    report_status: ReportStatus
    sample_metadata: dict[str, object]
    threat_assessment: dict[str, object]
    mitre_attack_capabilities: list[MitreAttackCapability]
    adversarial_evasion_findings: dict[str, object]
    executive_summary: str
    recommended_actions: list[str]
    abstention_metadata: NotRequired[dict[str, object]]
    status_flags: NotRequired[list[StatusFlag]]
