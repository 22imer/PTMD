"""Chốt hành vi Output Governance (spec §3.6, §4.2).

Kiểm ba lớp validate độc lập (schema, tham chiếu evidence, ràng buộc verdict),
vòng re-ask hữu hạn (≤2 lần sau lần sinh đầu) và Fallback Abstention không bao
giờ ép ``BENIGN``.
"""

from __future__ import annotations

import pytest

from guardrail.contracts import Verdict
from guardrail.report import (
    MAX_RE_ASKS,
    AbstentionRequired,
    AgentRequest,
    FallbackContractError,
    ReAskController,
    ReportValidator,
    build_fallback_report,
    collect_evidence_ids,
    validate_final_report,
)

SHA256 = "c" * 64
EVIDENCE_ID = "EVD-2026-0001"
DANGLING_ID = "EVD-2026-9999"
STORE = [{"evidence_id": EVIDENCE_ID}]


def _report(*, evidence_id: str = EVIDENCE_ID, verdict: str = "MALICIOUS") -> dict:
    return {
        "report_status": "COMPLETE",
        "sample_metadata": {
            "sha256": SHA256,
            "file_type": "PE32 executable",
            "packer_detected": "not detected",
        },
        "threat_assessment": {
            "verdict": verdict,
            "threat_score": 8 if verdict == "MALICIOUS" else 0,
            "confidence": 0.9 if verdict == "MALICIOUS" else 0.5,
        },
        "mitre_attack_capabilities": [
            {
                "tactic": "Execution",
                "technique_id": "T1059.003",
                "technique_name": "Windows Command Shell",
            }
        ],
        "adversarial_evasion_findings": {
            "prompt_injection_detected": True,
            "evasion_attempts": [
                {
                    "evidence_id": evidence_id,
                    "atlas_techniques": ["AML.T0051.001"],
                    "summary": "Chuỗi override quan sát trong telemetry.",
                }
            ],
        },
        "executive_summary": "Tóm tắt điều hành.",
        "recommended_actions": ["Chuyển analyst xem xét."],
    }


# --- Schema -----------------------------------------------------------------


def test_valid_report_passes_all_three_layers() -> None:
    result = validate_final_report(_report(), evidence_store=STORE)
    assert result.valid is True
    assert result.errors == []


def test_missing_required_field_is_a_validation_error() -> None:
    report = _report()
    del report["executive_summary"]
    result = validate_final_report(report, evidence_store=STORE)
    assert result.valid is False
    assert any("executive_summary" in error for error in result.errors)


def test_report_that_is_not_an_object_is_rejected() -> None:
    result = validate_final_report(["not", "a", "report"], evidence_store=STORE)
    assert result.valid is False
    assert "phải là object" in result.errors[0]


def test_schema_violation_reports_json_path() -> None:
    report = _report()
    report["threat_assessment"]["threat_score"] = 42  # vượt maximum 10
    result = validate_final_report(report, evidence_store=STORE)
    assert result.valid is False
    assert any(error.startswith("report.threat_assessment.threat_score") for error in result.errors)


# --- Tham chiếu evidence ----------------------------------------------------


def test_dangling_evidence_id_is_a_validation_error() -> None:
    result = validate_final_report(_report(evidence_id=DANGLING_ID), evidence_store=STORE)
    assert result.valid is False
    assert any(
        error.startswith("report.adversarial_evasion_findings.evasion_attempts[0].evidence_id")
        and DANGLING_ID in error
        for error in result.errors
    )


def test_evidence_reference_against_empty_store_is_rejected() -> None:
    result = validate_final_report(_report(), evidence_store=[])
    assert result.valid is False
    assert any(EVIDENCE_ID in error for error in result.errors)


def test_collect_evidence_ids_accepts_ids_records_and_mappings() -> None:
    assert collect_evidence_ids(["EVD-2026-0001", {"evidence_id": "EVD-2026-0002"}]) == {
        "EVD-2026-0001",
        "EVD-2026-0002",
    }
    assert collect_evidence_ids({"k": {"evidence_id": "EVD-2026-0003"}}) == {"EVD-2026-0003"}
    assert collect_evidence_ids(object()) == set()


# --- Ràng buộc verdict ------------------------------------------------------


def test_banned_verdict_is_rejected_and_never_coerced() -> None:
    report = _report(verdict="BENIGN")
    result = validate_final_report(
        report, evidence_store=STORE, banned_verdicts=(Verdict.BENIGN,)
    )
    assert result.valid is False
    assert any("BENIGN" in error and "bị cấm" in error for error in result.errors)
    # Không được sửa report để "hợp lệ": verdict gốc còn nguyên.
    assert report["threat_assessment"]["verdict"] == "BENIGN"


def test_unbanned_verdict_passes() -> None:
    result = validate_final_report(
        _report(verdict="INCONCLUSIVE"), evidence_store=STORE, banned_verdicts=(Verdict.BENIGN,)
    )
    assert result.valid is True


# --- Fallback abstention ----------------------------------------------------


def _fallback(**kwargs):
    return build_fallback_report(
        artifact_sha256=SHA256,
        file_type="PE32 executable",
        packer_detected="not detected",
        reason="pipeline coverage FAILED",
        **kwargs,
    )


def test_fallback_report_is_schema_valid_and_never_benign() -> None:
    report = _fallback(validation_errors=["report.x: thiếu trường"])
    result = validate_final_report(report)
    assert result.valid is True
    assert report["report_status"] == "ABSTAINED_PARTIAL"
    assert report["threat_assessment"]["verdict"] == "INCONCLUSIVE"
    assert report["threat_assessment"]["threat_score"] is None
    assert report["threat_assessment"]["confidence"] is None
    assert report["abstention_metadata"]["validation_errors"] == ["report.x: thiếu trường"]
    assert report["threat_assessment"]["verdict"] != "BENIGN"


def test_abstained_partial_consistency_is_enforced_beyond_schema() -> None:
    report = _fallback()
    report["threat_assessment"]["verdict"] = "BENIGN"
    result = validate_final_report(report)
    assert result.valid is False
    assert any("ABSTAINED_PARTIAL" in error for error in result.errors)


def test_abstained_partial_requires_null_score_and_confidence() -> None:
    report = _fallback()
    report["threat_assessment"]["threat_score"] = 3
    result = validate_final_report(report)
    assert result.valid is False
    assert any("threat_score" in error for error in result.errors)


def test_fallback_carries_capabilities_forward() -> None:
    report = _fallback(
        capabilities=[
            {
                "tactic": "Execution",
                "technique_id": "T1059.003",
                "technique_name": "Windows Command Shell",
                "namespace": "ignored",
            }
        ]
    )
    assert report["mitre_attack_capabilities"] == [
        {
            "tactic": "Execution",
            "technique_id": "T1059.003",
            "technique_name": "Windows Command Shell",
        }
    ]


# --- Re-ask loop ------------------------------------------------------------


def _controller(**kwargs) -> ReAskController:
    validator = ReportValidator(
        evidence_store=STORE, banned_verdicts=kwargs.pop("banned_verdicts", ())
    )
    return ReAskController(validator, **kwargs)


def test_reask_budget_is_one_initial_plus_two_reasks() -> None:
    assert MAX_RE_ASKS == 2
    assert _controller().max_attempts == 3


def test_invalid_output_is_reasked_with_concrete_errors_then_falls_back() -> None:
    requests: list[AgentRequest] = []

    def stubborn_agent(request: AgentRequest) -> dict:
        requests.append(request)
        return _report(evidence_id=DANGLING_ID)

    outcome = _controller().run(stubborn_agent, fallback_factory=lambda errors: _fallback(validation_errors=errors))

    assert outcome.attempts == 3
    assert outcome.abstained is True
    assert [request.attempt for request in requests] == [1, 2, 3]
    assert requests[0].errors == ()
    assert requests[1].errors == requests[2].errors != ()
    assert any(DANGLING_ID in error for error in requests[1].errors)
    assert outcome.errors == list(requests[2].errors)

    report = outcome.report
    assert report["report_status"] == "ABSTAINED_PARTIAL"
    assert report["threat_assessment"]["verdict"] == "INCONCLUSIVE"
    assert report["abstention_metadata"]["validation_errors"] == outcome.errors
    assert validate_final_report(report).valid is True


def test_reask_recovers_on_second_attempt() -> None:
    def flaky_agent(request: AgentRequest) -> dict:
        if request.attempt == 1:
            report = _report()
            del report["recommended_actions"]
            return report
        return _report()

    outcome = _controller().run(flaky_agent, fallback_factory=lambda errors: _fallback())
    assert outcome.attempts == 2
    assert outcome.abstained is False
    assert outcome.errors == []
    assert validate_final_report(outcome.report, evidence_store=STORE).valid is True


def test_banned_verdict_from_agent_ends_in_inconclusive_abstention() -> None:
    def benign_agent(request: AgentRequest) -> dict:
        return _report(verdict="BENIGN")

    outcome = _controller(banned_verdicts=(Verdict.BENIGN,)).run(
        benign_agent, fallback_factory=lambda errors: _fallback(validation_errors=errors)
    )
    assert outcome.abstained is True
    assert outcome.report["threat_assessment"]["verdict"] == "INCONCLUSIVE"
    assert outcome.report["threat_assessment"]["verdict"] != "BENIGN"


def test_without_factory_abstention_raises_with_errors() -> None:
    with pytest.raises(AbstentionRequired) as excinfo:
        _controller().run(lambda request: _report(evidence_id=DANGLING_ID))
    assert any(DANGLING_ID in error for error in excinfo.value.errors)


def test_invalid_fallback_is_rejected_by_contract_guard() -> None:
    broken = _fallback()
    del broken["abstention_metadata"]
    with pytest.raises(FallbackContractError):
        _controller().run(
            lambda request: _report(evidence_id=DANGLING_ID),
            fallback_factory=lambda errors: broken,
        )
