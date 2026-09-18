"""Guardrail chống Indirect Prompt Injection cho agent phân tích mã độc.

Package prototype Phase 2. Contract dữ liệu dùng chung nằm ở
`guardrail.contracts`; source of truth là hai schema trong `schemas/`
(spec v1.4.0 §4.1, §4.2).
"""

from guardrail.contracts import (
    DetectionMethod,
    DetectionSource,
    DetectionState,
    DetectorName,
    EvidenceRecord,
    FinalReport,
    MitreAtlasMapping,
    MitreAttackCapability,
    OwaspLlmMapping,
    PipelineAction,
    PolicyDecision,
    ProcessingState,
    Provenance,
    ProvenanceType,
    ReportStatus,
    StatusFlag,
    Verdict,
)

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
