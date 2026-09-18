"""Chốt contract T01: hai schema phải khớp nguyên văn spec v1.4.0, và các record
hợp lệ/không hợp lệ phải được JSON Schema Draft-07 chấp nhận/từ chối đúng như
schema mã hoá.

Test chỉ kiểm những gì schema mã hoá. Các quy tắc nằm ở văn xuôi spec (ví dụ
`ABSTAINED_PARTIAL` MUST kèm `abstention_metadata`) không được dựng thành assertion
bổ sung ở đây.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Callable

import jsonschema
import pytest

from guardrail.contracts import (
    DetectionSource,
    DetectionState,
    DetectorName,
    OwaspLlmMapping,
    PipelineAction,
    PolicyDecision,
    ProcessingState,
    ProvenanceType,
    ReportStatus,
    StatusFlag,
    Verdict,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = REPO_ROOT / "specs" / "guardrail_malware_agent_spec.md"

EVIDENCE_SCHEMA_PATH = REPO_ROOT / "schemas" / "quarantined_evidence.schema.json"
REPORT_SCHEMA_PATH = REPO_ROOT / "schemas" / "final_report.schema.json"

EVIDENCE_TITLE = "QuarantinedAdversarialEvidence"
REPORT_TITLE = "MalwareAgentFinalReport"


def _json_blocks(text: str) -> list[object]:
    """Parse mọi block ```json ... ``` trong `text`, theo thứ tự xuất hiện."""
    lines = text.split("\n")
    blocks: list[object] = []
    start: int | None = None
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith("```json"):
            start = idx
        elif line.strip() == "```" and start is not None:
            blocks.append(json.loads("\n".join(lines[start : idx - 1])))
            start = None
    assert start is None, "spec có block ```json không đóng"
    return blocks


@pytest.fixture(scope="module")
def spec_blocks() -> list[object]:
    return _json_blocks(SPEC_PATH.read_text(encoding="utf-8"))


def _schema_block(spec_blocks: list[object], title: str) -> dict:
    matches = [
        b
        for b in spec_blocks
        if isinstance(b, dict) and b.get("title") == title and "$schema" in b
    ]
    assert len(matches) == 1, f"spec phải có đúng một schema JSON cho title {title!r}"
    return matches[0]


def _evidence_examples(spec_blocks: list[object]) -> list[dict]:
    """Hai ví dụ bản ghi hợp lệ ở spec §4.3 (có `evidence_id`, không có `$schema`)."""
    examples = [
        b
        for b in spec_blocks
        if isinstance(b, dict) and "evidence_id" in b and "$schema" not in b
    ]
    assert len(examples) == 2, "spec §4.3 phải có đúng hai ví dụ evidence hợp lệ"
    return examples


@pytest.fixture(scope="module")
def evidence_schema() -> dict:
    return json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def report_schema() -> dict:
    return json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def base_evidence(spec_blocks: list[object]) -> dict:
    """Ví dụ §4.3 Valid 1 — dùng làm nền cho các ca invalid."""
    return _evidence_examples(spec_blocks)[0]


def test_schemas_are_valid_draft07(evidence_schema: dict, report_schema: dict) -> None:
    jsonschema.Draft7Validator.check_schema(evidence_schema)
    jsonschema.Draft7Validator.check_schema(report_schema)
    assert evidence_schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert report_schema["$schema"] == "http://json-schema.org/draft-07/schema#"


def test_schemas_match_spec_source(spec_blocks: list[object]) -> None:
    for path, title in (
        (EVIDENCE_SCHEMA_PATH, EVIDENCE_TITLE),
        (REPORT_SCHEMA_PATH, REPORT_TITLE),
    ):
        on_disk = json.loads(path.read_text(encoding="utf-8"))
        assert on_disk == _schema_block(spec_blocks, title), (
            f"{path.name} không còn khớp block JSON của {title} trong spec"
        )


def test_valid_examples_from_spec(
    spec_blocks: list[object], evidence_schema: dict
) -> None:
    for example in _evidence_examples(spec_blocks):
        jsonschema.validate(example, evidence_schema)


def _drop_provenance(base: dict) -> dict:
    instance = copy.deepcopy(base)
    del instance["provenance"]
    return instance


def _virtual_address_without_parent_hash(base: dict) -> dict:
    instance = copy.deepcopy(base)
    assert instance["provenance"]["type"] == "VIRTUAL_ADDRESS"
    del instance["provenance"]["parent_artifact_sha256"]
    return instance


def _sentinel_mapping_without_reason(base: dict) -> dict:
    instance = copy.deepcopy(base)
    instance["mitre_atlas_mappings"] = [
        {"technique_id": "No direct mapping", "technique_name": "No direct mapping"}
    ]
    return instance


def _pipeline_action_outside_enum(base: dict) -> dict:
    """`ALLOW` có trong ma trận §3.5.1 nhưng bị loại khỏi enum schema §4.1 (D03)."""
    assert "ALLOW" not in tuple(PipelineAction)
    instance = copy.deepcopy(base)
    instance["pipeline_action"] = "ALLOW"
    return instance


def _evidence_id_bad_pattern(base: dict) -> dict:
    instance = copy.deepcopy(base)
    instance["evidence_id"] = "EVD-26-0101"
    return instance


def _artifact_sha256_bad_pattern(base: dict) -> dict:
    instance = copy.deepcopy(base)
    instance["artifact_sha256"] = "a" * 63
    return instance


INVALID_CASES: dict[str, Callable[[dict], dict]] = {
    "thieu_provenance": _drop_provenance,
    "virtual_address_thieu_parent_artifact_sha256": _virtual_address_without_parent_hash,
    "sentinel_no_mapping_thieu_no_mapping_reason": _sentinel_mapping_without_reason,
    "pipeline_action_ngoai_enum": _pipeline_action_outside_enum,
    "evidence_id_sai_pattern": _evidence_id_bad_pattern,
    "artifact_sha256_sai_pattern": _artifact_sha256_bad_pattern,
}


@pytest.mark.parametrize("case_name", sorted(INVALID_CASES))
def test_invalid_examples_rejected(
    case_name: str, base_evidence: dict, evidence_schema: dict
) -> None:
    instance = INVALID_CASES[case_name](base_evidence)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance, evidence_schema)


COMPLETE_REPORT = {
    "report_status": "COMPLETE",
    "sample_metadata": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_type": "PE32 executable (GUI) Intel 80386",
        "packer_detected": "none",
    },
    "threat_assessment": {
        "verdict": "MALICIOUS",
        "threat_score": 8,
        "confidence": 0.93,
    },
    "mitre_attack_capabilities": [
        {
            "tactic": "Persistence",
            "technique_id": "T1547.001",
            "technique_name": "Registry Run Keys / Startup Folder",
        }
    ],
    "adversarial_evasion_findings": {
        "prompt_injection_detected": True,
        "evasion_attempts": [
            {
                "evidence_id": "EVD-2026-0101",
                "atlas_techniques": ["AML.T0051.001"],
                "summary": "Chuỗi override chỉ thị trong vùng .rsrc của mẫu.",
            }
        ],
    },
    "executive_summary": "Mẫu ghi Run key và chứa promptware tĩnh trong .rsrc.",
    "recommended_actions": ["Cách ly mẫu", "Thu hồi persistence Run key"],
}

ABSTAINED_PARTIAL_REPORT = {
    "report_status": "ABSTAINED_PARTIAL",
    "sample_metadata": {
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "file_type": "PE32 executable (DLL)",
        "packer_detected": "UPX 4.2",
    },
    "threat_assessment": {
        "verdict": "INCONCLUSIVE",
        "threat_score": None,
        "confidence": None,
    },
    "abstention_metadata": {
        "reason": "Hết lượt Re-ask sau hai lần output không hợp schema.",
        "validation_errors": [
            "evidence_id 'EVD-2026-9999' không tồn tại trong kho evidence cùng artifact"
        ],
    },
    "mitre_attack_capabilities": [],
    "adversarial_evasion_findings": {
        "prompt_injection_detected": False,
        "evasion_attempts": [],
    },
    "executive_summary": "Không đủ coverage để kết luận; cần review thủ công.",
    "recommended_actions": ["Review thủ công trước khi phát hành verdict"],
}


def test_report_schema(report_schema: dict) -> None:
    jsonschema.validate(COMPLETE_REPORT, report_schema)
    jsonschema.validate(ABSTAINED_PARTIAL_REPORT, report_schema)


def test_contract_enums_match_schema(evidence_schema: dict, report_schema: dict) -> None:
    evidence_props = evidence_schema["properties"]
    report_props = report_schema["properties"]

    def enum_of(schema_part: dict) -> set[str]:
        return set(schema_part["enum"])

    assert set(ProvenanceType) == enum_of(evidence_props["provenance"]["properties"]["type"])
    assert set(DetectionSource) == enum_of(evidence_props["detection_source"])
    assert set(DetectorName) == enum_of(
        evidence_props["detection_methods"]["items"]["properties"]["detector_name"]
    )
    assert set(OwaspLlmMapping) == enum_of(evidence_props["owasp_llm_mapping"])
    assert set(PolicyDecision) == enum_of(evidence_props["policy_decision"])
    assert set(PipelineAction) == enum_of(evidence_props["pipeline_action"])
    assert set(StatusFlag) == enum_of(evidence_props["status_flags"]["items"])
    assert set(ReportStatus) == enum_of(report_props["report_status"])
    assert set(Verdict) == enum_of(report_props["threat_assessment"]["properties"]["verdict"])
    assert set(StatusFlag) == enum_of(report_props["status_flags"]["items"])

    # Hai trục trạng thái không nằm trong schema (§3.5.1, §3.5.1.1) nhưng phải
    # khớp vocabulary của ma trận quyết định.
    assert set(ProcessingState) == {"COMPLETE", "PARTIAL", "FAILED"}
    assert set(DetectionState) == {"DETECTED", "NOT_DETECTED", "INCONCLUSIVE"}
    assert not set(ProcessingState) & set(DetectionState)
