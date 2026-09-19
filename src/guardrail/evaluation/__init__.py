"""Giao thức đánh giá (Phase 3, T09).

Manifest ghép cặp, ground truth và split chống rò rỉ theo spec v1.4.0 §6.1–6.2
nằm ở `guardrail.evaluation.dataset_protocol`. Các module metric/baseline của
T10 đặt cùng package này (``evaluation/metrics.py``) — ``evaluation`` là package,
không phải module đơn.
"""

from guardrail.evaluation.dataset_protocol import (
    BENIGN_ORIGIN_PAIRS,
    CALIBRATION_PAIRS,
    DATASET_SCHEMA_VERSION,
    GROUP_RULES,
    GROUP_SIZE,
    INSERTION_LOCI,
    MALWARE_ORIGIN_PAIRS,
    MIN_JACCARD,
    ORIGIN_BALANCE,
    TEST_PAIRS,
    TOTAL_PAIRS,
    DatasetCounts,
    DatasetError,
    DatasetValidationReport,
    MalwareBehavior,
    MemberRole,
    PairOrigin,
    PairRejection,
    Split,
    format_metric,
    load_manifest,
    validate_manifest,
    validate_manifest_file,
)

__all__ = [
    "BENIGN_ORIGIN_PAIRS",
    "CALIBRATION_PAIRS",
    "DATASET_SCHEMA_VERSION",
    "GROUP_RULES",
    "GROUP_SIZE",
    "INSERTION_LOCI",
    "MALWARE_ORIGIN_PAIRS",
    "MIN_JACCARD",
    "ORIGIN_BALANCE",
    "TEST_PAIRS",
    "TOTAL_PAIRS",
    "DatasetCounts",
    "DatasetError",
    "DatasetValidationReport",
    "MalwareBehavior",
    "MemberRole",
    "PairOrigin",
    "PairRejection",
    "Split",
    "format_metric",
    "load_manifest",
    "validate_manifest",
    "validate_manifest_file",
]
