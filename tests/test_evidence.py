"""Chốt hành vi sinh bản ghi Quarantined Evidence (spec v1.4.0 §3.5.1, §4.1, §5).

Mọi bản ghi do `guardrail.evidence` phát hành phải qua được
`schemas/quarantined_evidence.schema.json` bằng `jsonschema` (Draft-07). Ngoài ra
test chốt ánh xạ action ➔ bản ghi của §3.5.1 (ALLOW không bản ghi; quarantine
đúng hai bản ghi; escalate kèm coverage gap; abstention kèm tham chiếu raw
telemetry), Finding Preservation Rule ở hàng 4 và hàng 7, cùng hai bản ghi Lớp 5
(`READ_ONLY_DISPATCHER`/`HARD_BLOCK` và `CANARY_VERIFIER`/`AGENT_OUTPUT`).
"""

from __future__ import annotations

import json
from pathlib import Path

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
    StatusFlag,
)
from guardrail.evidence import (
    EvidenceContractError,
    NO_MAPPING_TECHNIQUE,
    build_canary_leak_evidence,
    build_dispatcher_block_evidence,
    build_evidence_record,
    build_finding_evidence,
    build_provenance,
    emit_policy_evidence,
    format_evidence_id,
)
from guardrail.policy import DECISION_MATRIX, PolicyAction, decide, evaluate_policy

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_SCHEMA_PATH = REPO_ROOT / "schemas" / "quarantined_evidence.schema.json"

ARTIFACT_SHA256 = "a" * 64
PARENT_SHA256 = "b" * 64
YEAR = 2026


@pytest.fixture(scope="module")
def validator() -> jsonschema.Draft7Validator:
    schema = json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))
    return jsonschema.Draft7Validator(schema)


def _assert_valid(validator: jsonschema.Draft7Validator, record: dict) -> None:
    errors = sorted(validator.iter_errors(record), key=lambda error: list(error.path))
    assert not errors, "\n".join(
        f"{list(error.path)}: {error.message}" for error in errors
    )


def _finding(**overrides: object) -> dict:
    finding: dict = {
        "detector_name": DetectorName.YARA_STATIC,
        "rule_or_model_version": "rules-1.4.0",
        "score": 0.97,
        "detection_source": DetectionSource.STATIC_STRING,
        "provenance": {"type": ProvenanceType.FILE_OFFSET, "locator": "offset:0x40"},
        "interpretation_summary": "Chuỗi chỉ thị đối kháng nằm trong section .data.",
        "transform_chain": ["BASE64_D1"],
        "owasp_llm_mapping": OwaspLlmMapping.PROMPT_INJECTION,
    }
    finding.update(overrides)
    return finding


def _memory_finding() -> dict:
    return _finding(
        detector_name=DetectorName.YARA_CUCKOO,
        detection_source=DetectionSource.DYNAMIC_MEMORY_DUMP,
        provenance={
            "type": ProvenanceType.VIRTUAL_ADDRESS,
            "locator": "0x000412A0",
            "section_or_pid": "4128",
            "parent_artifact_sha256": PARENT_SHA256,
        },
    )


def _seed(**overrides: object) -> dict:
    seed: dict = {
        "detection_methods": [
            {
                "detector_name": DetectorName.TELEMETRY_ADAPTER,
                "rule_or_model_version": "capev2-2.2",
                "score": 0.4,
            }
        ],
        "detection_source": DetectionSource.SANDBOX_API_LOG,
        "provenance": {
            "type": ProvenanceType.JSON_LOG_POINTER,
            "locator": "/behavior/processes/0/calls/3",
        },
        "interpretation_summary": "Các detector bắt buộc không đồng thuận trên cùng phạm vi artifact.",
    }
    seed.update(overrides)
    return seed


def _record(*, seed: dict | None = None, **kwargs: object) -> dict:
    arguments: dict = {
        "evidence_id": format_evidence_id(YEAR, 1),
        "artifact_sha256": ARTIFACT_SHA256,
        "policy_decision": PolicyDecision.TAG_AS_EVIDENCE,
        "pipeline_action": PipelineAction.TAG_AS_EVIDENCE,
    }
    arguments.update(kwargs)
    return build_evidence_record(seed if seed is not None else _seed(), **arguments)


# --- Bản ghi TAG_AS_EVIDENCE ---------------------------------------------


def test_tag_as_evidence_record_matches_envelope(validator: jsonschema.Draft7Validator) -> None:
    """Bản ghi finding đúng envelope §4.3 và có sentinel no-mapping khi thiếu ATLAS."""
    record = build_finding_evidence(
        _finding(),
        evidence_id=format_evidence_id(YEAR, 1),
        artifact_sha256=ARTIFACT_SHA256,
        pipeline_action=PipelineAction.TAG_AS_EVIDENCE,
    )
    _assert_valid(validator, record)
    assert record["evidence_id"] == "EVD-2026-0001"
    assert record["artifact_sha256"] == ARTIFACT_SHA256
    assert record["policy_decision"] == PolicyDecision.TAG_AS_EVIDENCE
    assert record["pipeline_action"] == PipelineAction.TAG_AS_EVIDENCE
    assert record["status_flags"] == []
    assert record["detection_methods"] == [
        {
            "detector_name": DetectorName.YARA_STATIC,
            "rule_or_model_version": "rules-1.4.0",
            "score": 0.97,
        }
    ]
    mapping = record["mitre_atlas_mappings"][0]
    assert mapping["technique_id"] == NO_MAPPING_TECHNIQUE
    assert mapping["technique_name"] == NO_MAPPING_TECHNIQUE
    assert mapping["no_mapping_reason"]
    assert record["transform_chain"] == ["BASE64_D1"]
    json.dumps(record, ensure_ascii=False)


def test_tag_as_evidence_uses_seed_when_no_single_finding(validator: jsonschema.Draft7Validator) -> None:
    """Hàng 1 vẫn phát hành được bản ghi khi caller chỉ có ngữ cảnh phát hiện."""
    outcome = decide(ProcessingState.COMPLETE, DetectionState.DETECTED)
    records = emit_policy_evidence(
        outcome,
        artifact_sha256=ARTIFACT_SHA256,
        year=YEAR,
        first_sequence=1,
        detection=_seed(),
    )
    assert len(records) == 1
    assert records[0]["policy_decision"] == PolicyDecision.TAG_AS_EVIDENCE
    assert records[0]["pipeline_action"] == PipelineAction.TAG_AS_EVIDENCE
    _assert_valid(validator, records[0])


# --- ALLOW không sinh bản ghi ---------------------------------------------


def test_allow_emits_no_record() -> None:
    """`ALLOW` ➔ không phát hành bản ghi (§3.5.1)."""
    outcome = decide(ProcessingState.COMPLETE, DetectionState.NOT_DETECTED)
    assert (
        emit_policy_evidence(
            outcome, artifact_sha256=ARTIFACT_SHA256, year=YEAR, first_sequence=1
        )
        == []
    )


# --- CAUTIOUS_QUARANTINE ➔ đúng hai bản ghi -------------------------------


def test_cautious_quarantine_emits_exactly_two_records(
    validator: jsonschema.Draft7Validator,
) -> None:
    """Quarantine phát hành `SANITIZE_AND_STRIP` (lưu trữ) + `ESCALATE_TO_HUMAN` (P2)."""
    outcome = decide(ProcessingState.COMPLETE, DetectionState.INCONCLUSIVE)
    records = emit_policy_evidence(
        outcome,
        artifact_sha256=ARTIFACT_SHA256,
        year=YEAR,
        first_sequence=7,
        detection=_seed(),
    )
    assert [record["policy_decision"] for record in records] == [
        PolicyDecision.SANITIZE_AND_STRIP,
        PolicyDecision.ESCALATE_TO_HUMAN,
    ]
    assert {record["pipeline_action"] for record in records} == {
        PipelineAction.CAUTIOUS_QUARANTINE
    }
    assert [record["evidence_id"] for record in records] == [
        "EVD-2026-0007",
        "EVD-2026-0008",
    ]
    assert all(
        record["status_flags"] == [StatusFlag.DETECTOR_DISAGREEMENT]
        for record in records
    )
    for record in records:
        _assert_valid(validator, record)


# --- ESCALATE_AND_INCONCLUSIVE ➔ finding + coverage gap -------------------


def test_escalate_and_inconclusive_emits_finding_then_coverage_gap(
    validator: jsonschema.Draft7Validator,
) -> None:
    """Hàng 4: finding vẫn được TAG_AS_EVIDENCE dù coverage bị cắt cụt."""
    outcome = decide(ProcessingState.PARTIAL, DetectionState.DETECTED)
    assert outcome.forward_to_agent is True

    records = emit_policy_evidence(
        outcome,
        artifact_sha256=ARTIFACT_SHA256,
        year=YEAR,
        first_sequence=11,
        findings=[_finding()],
        detection=_seed(),
    )
    assert [record["policy_decision"] for record in records] == [
        PolicyDecision.TAG_AS_EVIDENCE,
        PolicyDecision.ESCALATE_TO_HUMAN,
    ]
    assert all(
        record["pipeline_action"] == PipelineAction.ESCALATE_AND_INCONCLUSIVE
        for record in records
    )
    assert all(
        record["status_flags"] == [StatusFlag.TRUNCATED_ARTIFACT_FLAG]
        for record in records
    )
    assert records[0]["detection_methods"][0]["detector_name"] == DetectorName.YARA_STATIC
    assert records[0]["evidence_id"] == "EVD-2026-0011"
    assert records[1]["evidence_id"] == "EVD-2026-0012"
    for record in records:
        _assert_valid(validator, record)


def test_partial_not_detected_emits_only_coverage_gap(
    validator: jsonschema.Draft7Validator,
) -> None:
    """Hàng 5: không có finding thì chỉ có bản ghi escalation cho coverage gap."""
    outcome = decide(ProcessingState.PARTIAL, DetectionState.NOT_DETECTED)
    records = emit_policy_evidence(
        outcome,
        artifact_sha256=ARTIFACT_SHA256,
        year=YEAR,
        first_sequence=1,
        detection=_seed(),
    )
    assert [record["policy_decision"] for record in records] == [
        PolicyDecision.ESCALATE_TO_HUMAN
    ]
    _assert_valid(validator, records[0])


# --- PIPELINE_ABSTENTION ➔ raw telemetry + bảo toàn finding ---------------


def test_pipeline_abstention_keeps_finding_but_never_forwards(
    validator: jsonschema.Draft7Validator,
) -> None:
    """Hàng 7: không chuyển tiếp context nhưng positive finding vẫn thành bản ghi."""
    results = [
        {"name": "YARA_CUCKOO", "positive": True, "errored": False, "score": 1.0},
        {"name": "TELEMETRY_ADAPTER", "positive": False, "errored": True, "score": 0.0},
    ]
    evaluation = evaluate_policy(
        results, ("YARA_CUCKOO", "TELEMETRY_ADAPTER"), ProcessingState.FAILED
    )
    assert evaluation.detection_state is DetectionState.DETECTED
    outcome = evaluation.outcome
    assert outcome.forward_to_agent is False
    assert outcome.escalation_immediate is True

    raw_telemetry = {
        "type": ProvenanceType.JSON_LOG_POINTER,
        "locator": f"evidence_store://raw_telemetry/{ARTIFACT_SHA256}",
    }
    records = emit_policy_evidence(
        outcome,
        artifact_sha256=ARTIFACT_SHA256,
        year=YEAR,
        first_sequence=21,
        findings=[_memory_finding()],
        detection=_seed(),
        raw_telemetry=raw_telemetry,
    )
    assert [record["policy_decision"] for record in records] == [
        PolicyDecision.ESCALATE_TO_HUMAN,
        PolicyDecision.TAG_AS_EVIDENCE,
    ]
    assert all(
        record["pipeline_action"] == PipelineAction.PIPELINE_ABSTENTION
        for record in records
    )
    assert records[0]["provenance"]["locator"] == raw_telemetry["locator"]
    preserved = records[1]
    assert preserved["provenance"]["type"] == ProvenanceType.VIRTUAL_ADDRESS
    assert preserved["provenance"]["parent_artifact_sha256"] == PARENT_SHA256
    assert preserved["detection_methods"][0]["detector_name"] == DetectorName.YARA_CUCKOO
    for record in records:
        _assert_valid(validator, record)


def test_pipeline_abstention_without_finding_emits_single_escalation(
    validator: jsonschema.Draft7Validator,
) -> None:
    """Hàng 8/9: abstention không có finding thì chỉ phát hành escalation."""
    outcome = decide(ProcessingState.FAILED, DetectionState.NOT_DETECTED)
    records = emit_policy_evidence(
        outcome,
        artifact_sha256=ARTIFACT_SHA256,
        year=YEAR,
        first_sequence=1,
        detection=_seed(),
    )
    assert [record["policy_decision"] for record in records] == [
        PolicyDecision.ESCALATE_TO_HUMAN
    ]
    _assert_valid(validator, records[0])


# --- Bản ghi Lớp 5 --------------------------------------------------------


def test_dispatcher_hard_block_record(validator: jsonschema.Draft7Validator) -> None:
    """`HARD_BLOCK` của Dispatcher Lớp 5 ghim đúng nguồn/phương thức phát hiện."""
    record = build_dispatcher_block_evidence(
        evidence_id=format_evidence_id(YEAR, 41),
        artifact_sha256=ARTIFACT_SHA256,
        rule_or_model_version="dispatcher-v1",
        score=1.0,
        provenance={
            "type": ProvenanceType.RUNTIME_TOOL_CALL,
            "locator": "tool_call:run_shell('powershell -enc ...')",
        },
        interpretation_summary="Agent gọi tool ngoài ba hàm read-only; lời gọi đã bị chặn.",
    )
    _assert_valid(validator, record)
    assert record["detection_source"] == DetectionSource.RUNTIME_TOOL_CALL
    assert record["detection_methods"][0]["detector_name"] == DetectorName.READ_ONLY_DISPATCHER
    assert record["policy_decision"] == PolicyDecision.HARD_BLOCK
    assert record["pipeline_action"] == PipelineAction.HARD_BLOCK
    assert record["owasp_llm_mapping"] == OwaspLlmMapping.EXCESSIVE_AGENCY
    assert record["mitre_atlas_mappings"][0]["technique_id"] == "AML.T0053"


def test_dispatcher_record_requires_runtime_tool_call_provenance() -> None:
    """Không thể dán nhãn HARD_BLOCK cho một provenance không phải tool-call."""
    with pytest.raises(EvidenceContractError):
        build_dispatcher_block_evidence(
            evidence_id=format_evidence_id(YEAR, 41),
            artifact_sha256=ARTIFACT_SHA256,
            rule_or_model_version="dispatcher-v1",
            score=1.0,
            provenance={"type": ProvenanceType.FILE_OFFSET, "locator": "offset:0x40"},
            interpretation_summary="sai provenance",
        )


def test_canary_leak_record(validator: jsonschema.Draft7Validator) -> None:
    """Rò rỉ canary ở Lớp 5 dùng `AGENT_OUTPUT`/`CANARY_VERIFIER` (spec §4.3 ví dụ 2)."""
    record = build_canary_leak_evidence(
        evidence_id=format_evidence_id(YEAR, 107),
        artifact_sha256=ARTIFACT_SHA256,
        rule_or_model_version="canary-v1",
        score=1.0,
        provenance={
            "type": ProvenanceType.AGENT_OUTPUT,
            "locator": "report.executive_summary",
            "section_or_pid": None,
        },
        interpretation_summary="Output chứa canary; nội dung rò rỉ đã bị tước trước khi phát hành.",
    )
    _assert_valid(validator, record)
    assert record["detection_source"] == DetectionSource.AGENT_OUTPUT
    assert record["detection_methods"][0]["detector_name"] == DetectorName.CANARY_VERIFIER
    assert record["policy_decision"] == PolicyDecision.TAG_AS_EVIDENCE
    assert record["pipeline_action"] == PipelineAction.TAG_AS_EVIDENCE
    assert record["owasp_llm_mapping"] == OwaspLlmMapping.SYSTEM_PROMPT_LEAKAGE
    assert record["mitre_atlas_mappings"][0]["technique_id"] == "AML.T0056"


def test_canary_record_requires_agent_output_provenance() -> None:
    """Bản ghi canary không nhận provenance ngoài `AGENT_OUTPUT`."""
    with pytest.raises(EvidenceContractError):
        build_canary_leak_evidence(
            evidence_id=format_evidence_id(YEAR, 108),
            artifact_sha256=ARTIFACT_SHA256,
            rule_or_model_version="canary-v1",
            score=1.0,
            provenance={
                "type": ProvenanceType.VIRTUAL_ADDRESS,
                "locator": "0x000412A0",
                "parent_artifact_sha256": PARENT_SHA256,
            },
            interpretation_summary="sai provenance",
        )


# --- Bao phủ toàn ma trận -------------------------------------------------

MATRIX_CELLS = list(DECISION_MATRIX)


@pytest.mark.parametrize(
    ("processing_state", "detection_state"),
    MATRIX_CELLS,
    ids=[f"{cell[0]}-{cell[1]}" for cell in MATRIX_CELLS],
)
def test_every_matrix_outcome_emits_schema_valid_records(
    validator: jsonschema.Draft7Validator,
    processing_state: ProcessingState,
    detection_state: DetectionState,
) -> None:
    """Mọi ô ma trận: đúng số bản ghi tối thiểu và mọi bản ghi đều hợp lệ §4.1."""
    outcome = decide(processing_state, detection_state)
    records = emit_policy_evidence(
        outcome,
        artifact_sha256=ARTIFACT_SHA256,
        year=YEAR,
        first_sequence=1,
        findings=[_finding(), _memory_finding()],
        detection=_seed(),
    )
    for record in records:
        _assert_valid(validator, record)

    if outcome.pipeline_action is PolicyAction.ALLOW:
        assert records == []
        return

    assert records, f"{processing_state}/{detection_state} phải phát hành bản ghi"
    findings_emitted = [
        record["policy_decision"] for record in records
    ].count(PolicyDecision.TAG_AS_EVIDENCE)
    # Chỉ CAUTIOUS_QUARANTINE không phát hành bản ghi cho từng finding (§3.5.1).
    expected_findings = (
        0 if outcome.pipeline_action is PolicyAction.CAUTIOUS_QUARANTINE else 2
    )
    assert findings_emitted == expected_findings
    if processing_state is ProcessingState.PARTIAL:
        assert any(
            StatusFlag.TRUNCATED_ARTIFACT_FLAG in record["status_flags"]
            for record in records
        )


def test_emit_requires_detection_seed_for_quarantine_paths() -> None:
    """Thiếu ngữ cảnh phát hiện/coverage gap là lỗi hợp đồng, không phát hành rỗng."""
    with pytest.raises(EvidenceContractError):
        emit_policy_evidence(
            decide(ProcessingState.COMPLETE, DetectionState.INCONCLUSIVE),
            artifact_sha256=ARTIFACT_SHA256,
            year=YEAR,
            first_sequence=1,
        )
    with pytest.raises(EvidenceContractError):
        emit_policy_evidence(
            decide(ProcessingState.PARTIAL, DetectionState.DETECTED),
            artifact_sha256=ARTIFACT_SHA256,
            year=YEAR,
            first_sequence=1,
            findings=[_finding()],
        )
    with pytest.raises(EvidenceContractError):
        emit_policy_evidence(
            decide(ProcessingState.COMPLETE, DetectionState.DETECTED),
            artifact_sha256=ARTIFACT_SHA256,
            year=YEAR,
            first_sequence=1,
        )


def test_emit_rejects_action_outside_matrix() -> None:
    """`HARD_BLOCK` không thuộc ma trận nên phải đi qua builder chuyên biệt Lớp 5."""
    outcome = decide(ProcessingState.COMPLETE, DetectionState.DETECTED)
    hard_block = outcome._replace(pipeline_action="HARD_BLOCK")
    with pytest.raises(EvidenceContractError):
        emit_policy_evidence(
            hard_block,
            artifact_sha256=ARTIFACT_SHA256,
            year=YEAR,
            first_sequence=1,
            findings=[_finding()],
        )


# --- Kiểm tra đầu vào -----------------------------------------------------


INVALID_RECORDS = [
    ("evidence-id-sai-pattern", lambda: _record(evidence_id="EVD-26-1")),
    ("artifact-sha-thieu-ky-tu", lambda: _record(artifact_sha256="a" * 63)),
    ("policy-decision-allow", lambda: _record(policy_decision="ALLOW")),
    ("pipeline-action-allow", lambda: _record(pipeline_action="ALLOW")),
    (
        "virtual-address-thieu-parent",
        lambda: _record(
            seed=_seed(
                provenance={
                    "type": ProvenanceType.VIRTUAL_ADDRESS,
                    "locator": "0x000412A0",
                }
            )
        ),
    ),
    (
        "virtual-address-locator-sai-dang",
        lambda: _record(
            seed=_seed(
                provenance={
                    "type": ProvenanceType.VIRTUAL_ADDRESS,
                    "locator": "412A0",
                    "parent_artifact_sha256": PARENT_SHA256,
                }
            )
        ),
    ),
    ("detection-methods-rong", lambda: _record(seed=_seed(detection_methods=[]))),
    (
        "detection-score-ngoai-khoang",
        lambda: _record(
            seed=_seed(
                detection_methods=[
                    {
                        "detector_name": DetectorName.YARA_STATIC,
                        "rule_or_model_version": "rules-1.4.0",
                        "score": 1.5,
                    }
                ]
            )
        ),
    ),
    (
        "detector-name-ngoai-enum",
        lambda: _record(
            seed=_seed(
                detection_methods=[
                    {
                        "detector_name": "NMAP_SCANNER",
                        "rule_or_model_version": "1",
                        "score": 0.5,
                    }
                ]
            )
        ),
    ),
    ("detection-source-ngoai-enum", lambda: _record(seed=_seed(detection_source="UNKNOWN"))),
    ("interpretation-rong", lambda: _record(seed=_seed(interpretation_summary=""))),
    ("owasp-mapping-ngoai-enum", lambda: _record(seed=_seed(owasp_llm_mapping="LLM99:2025-Nope"))),
    ("confidence-ngoai-khoang", lambda: _record(seed=_seed(confidence_score=1.5))),
    ("provenance-khong-phai-object", lambda: _record(seed=_seed(provenance="offset:0x40"))),
    (
        "status-flags-trung-lap",
        lambda: _record(
            status_flags=[StatusFlag.TRUNCATED_ARTIFACT_FLAG, "TRUNCATED_ARTIFACT_FLAG"]
        ),
    ),
    ("status-flags-ngoai-enum", lambda: _record(status_flags=["NOT_A_FLAG"])),
    (
        "sentinel-atlas-name-lech",
        lambda: _record(
            seed=_seed(
                mitre_atlas_mappings=[
                    {
                        "technique_id": NO_MAPPING_TECHNIQUE,
                        "technique_name": "AML.T0051",
                    }
                ]
            )
        ),
    ),
]


@pytest.mark.parametrize(
    ("case", "builder"),
    INVALID_RECORDS,
    ids=[case[0] for case in INVALID_RECORDS],
)
def test_build_evidence_record_rejects_invalid_input(case: str, builder: object) -> None:
    """Vi phạm contract §4.1 bị từ chối ngay tại builder."""
    with pytest.raises(EvidenceContractError):
        builder()  # type: ignore[operator]


def test_sentinel_atlas_gets_default_no_mapping_reason(validator: jsonschema.Draft7Validator) -> None:
    """Sentinel no-mapping luôn kèm `no_mapping_reason` khác rỗng (§4.1)."""
    record = _record(
        seed=_seed(
            mitre_atlas_mappings=[
                {
                    "technique_id": NO_MAPPING_TECHNIQUE,
                    "technique_name": NO_MAPPING_TECHNIQUE,
                }
            ]
        )
    )
    _assert_valid(validator, record)
    reason = record["mitre_atlas_mappings"][0]["no_mapping_reason"]
    assert isinstance(reason, str) and reason


def test_confidence_defaults_to_highest_detector_score() -> None:
    """Không khai `confidence_score` thì lấy điểm detector cao nhất."""
    record = _record(
        seed=_seed(
            detection_methods=[
                {
                    "detector_name": DetectorName.YARA_STATIC,
                    "rule_or_model_version": "rules-1.4.0",
                    "score": 0.6,
                },
                {
                    "detector_name": DetectorName.META_PROMPT_GUARD,
                    "rule_or_model_version": "Prompt-Guard-86M",
                    "score": 0.82,
                },
            ]
        )
    )
    assert record["confidence_score"] == 0.82


def test_format_evidence_id_follows_schema_pattern() -> None:
    """`evidence_id` sinh theo pattern `^EVD-[0-9]{4}-[0-9]{4,}$`."""
    assert format_evidence_id(2026, 1) == "EVD-2026-0001"
    assert format_evidence_id(2026, 12345) == "EVD-2026-12345"
    with pytest.raises(EvidenceContractError):
        format_evidence_id(2026, 0)
    with pytest.raises(EvidenceContractError):
        format_evidence_id(10000, 1)


def test_build_provenance_enforces_virtual_address_contract() -> None:
    """`build_provenance` chốt ràng buộc `if/then` của `VIRTUAL_ADDRESS`."""
    provenance = build_provenance(
        ProvenanceType.VIRTUAL_ADDRESS,
        "0x000412A0",
        section_or_pid="4128",
        parent_artifact_sha256=PARENT_SHA256,
    )
    assert provenance == {
        "type": ProvenanceType.VIRTUAL_ADDRESS,
        "locator": "0x000412A0",
        "section_or_pid": "4128",
        "parent_artifact_sha256": PARENT_SHA256,
    }
    with pytest.raises(EvidenceContractError):
        build_provenance(ProvenanceType.VIRTUAL_ADDRESS, "0x000412A0")
    with pytest.raises(EvidenceContractError):
        build_provenance(
            ProvenanceType.FILE_OFFSET, "offset:0x40", parent_artifact_sha256="zz"
        )
