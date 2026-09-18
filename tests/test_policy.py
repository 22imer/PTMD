"""Chốt hành vi Decision Policy Gate — ma trận 9 ô & tổng hợp detector (spec v1.4.0 §3.5.1, §3.5.1.1).

Test so sánh **toàn bộ** tuple kết quả của từng ô (action, chuyển tiếp context,
sanitize, cờ trạng thái, escalation, escalation tức thời, ràng buộc verdict) chứ
không chỉ chuỗi action, và chứng minh cả 9 ô đều truy cập được từ kết quả
detector thật qua `evaluate_policy`.

Quy ước then chốt của §3.5.1.1 được kiểm tường minh: dương tính hợp lệ và âm
tính hợp lệ cùng tồn tại trên một phạm vi artifact là *bất đồng* ➔ `INCONCLUSIVE`;
một detector bắt buộc lỗi/thiếu trong khi coverage chưa `FAILED` cũng
`INCONCLUSIVE`; chỉ khi mọi detector bắt buộc chạy sạch âm tính mới `NOT_DETECTED`.
"""

from __future__ import annotations

import itertools

import pytest

from guardrail.contracts import (
    DetectionState,
    PipelineAction,
    ProcessingState,
    StatusFlag,
    Verdict,
)
from guardrail.policy import (
    DECISION_MATRIX,
    DecisionOutcome,
    Escalation,
    PolicyAction,
    aggregate_detection_state,
    decide,
    evaluate_policy,
    is_verdict_forbidden,
    to_pipeline_action,
)

ALL_VERDICTS = (
    Verdict.MALICIOUS,
    Verdict.SUSPICIOUS,
    Verdict.BENIGN,
    Verdict.INCONCLUSIVE,
)

#: 9 hàng của bảng §3.5.1 chép độc lập từ spec (không đọc lại `DECISION_MATRIX`).
#: (processing, detection, action, forward, sanitize, flags, escalation, immediate, banned)
EXPECTED_ROWS: list[tuple[object, ...]] = [
    (
        ProcessingState.COMPLETE,
        DetectionState.DETECTED,
        PolicyAction.TAG_AS_EVIDENCE,
        True,
        True,
        (),
        Escalation.P3,
        False,
        (),
    ),
    (
        ProcessingState.COMPLETE,
        DetectionState.NOT_DETECTED,
        PolicyAction.ALLOW,
        True,
        False,
        (),
        None,
        False,
        (),
    ),
    (
        ProcessingState.COMPLETE,
        DetectionState.INCONCLUSIVE,
        PolicyAction.CAUTIOUS_QUARANTINE,
        True,
        True,
        (StatusFlag.DETECTOR_DISAGREEMENT,),
        Escalation.P2,
        False,
        (Verdict.BENIGN,),
    ),
    (
        ProcessingState.PARTIAL,
        DetectionState.DETECTED,
        PolicyAction.ESCALATE_AND_INCONCLUSIVE,
        True,
        True,
        (StatusFlag.TRUNCATED_ARTIFACT_FLAG,),
        Escalation.P1,
        False,
        (Verdict.BENIGN,),
    ),
    (
        ProcessingState.PARTIAL,
        DetectionState.NOT_DETECTED,
        PolicyAction.ESCALATE_AND_INCONCLUSIVE,
        True,
        True,
        (StatusFlag.TRUNCATED_ARTIFACT_FLAG,),
        Escalation.P1,
        False,
        (Verdict.BENIGN,),
    ),
    (
        ProcessingState.PARTIAL,
        DetectionState.INCONCLUSIVE,
        PolicyAction.ESCALATE_AND_INCONCLUSIVE,
        True,
        True,
        (StatusFlag.TRUNCATED_ARTIFACT_FLAG, StatusFlag.DETECTOR_DISAGREEMENT),
        Escalation.P1,
        False,
        (Verdict.BENIGN,),
    ),
    (
        ProcessingState.FAILED,
        DetectionState.DETECTED,
        PolicyAction.PIPELINE_ABSTENTION,
        False,
        True,
        (StatusFlag.TRUNCATED_ARTIFACT_FLAG,),
        Escalation.P1,
        True,
        ALL_VERDICTS,
    ),
    (
        ProcessingState.FAILED,
        DetectionState.NOT_DETECTED,
        PolicyAction.PIPELINE_ABSTENTION,
        False,
        True,
        (StatusFlag.TRUNCATED_ARTIFACT_FLAG,),
        Escalation.P1,
        True,
        ALL_VERDICTS,
    ),
    (
        ProcessingState.FAILED,
        DetectionState.INCONCLUSIVE,
        PolicyAction.PIPELINE_ABSTENTION,
        False,
        True,
        (StatusFlag.TRUNCATED_ARTIFACT_FLAG,),
        Escalation.P1,
        True,
        ALL_VERDICTS,
    ),
]

ROW_IDS = [
    f"row{index}-{row[0]}-{row[1]}" for index, row in enumerate(EXPECTED_ROWS, start=1)
]


# --- Trợ giúp -------------------------------------------------------------


def _positive(name: str, *, has_provenance: bool = True, score: float = 1.0) -> dict:
    return {"name": name, "positive": True, "errored": False, "score": score, "has_provenance": has_provenance}


def _negative(name: str) -> dict:
    return {"name": name, "positive": False, "errored": False, "score": 0.1}


def _errored(name: str) -> dict:
    return {"name": name, "positive": False, "errored": True, "score": 0.0}


def _expected_outcome(row: tuple[object, ...]) -> DecisionOutcome:
    return DecisionOutcome(
        pipeline_action=row[2],
        forward_to_agent=row[3],
        sanitize_required=row[4],
        status_flags=row[5],
        escalation=row[6],
        escalation_immediate=row[7],
        banned_verdicts=row[8],
    )


# --- Ma trận 9 ô ----------------------------------------------------------


@pytest.mark.parametrize("row", EXPECTED_ROWS, ids=ROW_IDS)
def test_decision_matrix_row_matches_spec(row: tuple[object, ...]) -> None:
    """Mỗi ô trả về đúng toàn bộ tuple của bảng §3.5.1."""
    assert decide(row[0], row[1]) == _expected_outcome(row)


def test_decision_matrix_covers_exactly_nine_cells() -> None:
    """Ma trận có đúng 9 ô, phủ kín tích Processing × Detection."""
    assert set(DECISION_MATRIX) == set(
        itertools.product(ProcessingState, DetectionState)
    )
    assert len(DECISION_MATRIX) == 9


def test_hard_block_never_appears_in_matrix() -> None:
    """`HARD_BLOCK` thuộc Dispatcher Lớp 5, không có ô nào trong ma trận §3.5.1."""
    assert "HARD_BLOCK" not in {str(row[2]) for row in EXPECTED_ROWS}
    assert "HARD_BLOCK" not in {
        str(outcome.pipeline_action) for outcome in DECISION_MATRIX.values()
    }


def test_failed_rows_never_forward_and_ban_every_verdict() -> None:
    """Ba hàng FAILED không chuyển tiếp context và cấm mọi verdict."""
    for row in EXPECTED_ROWS:
        if row[0] is not ProcessingState.FAILED:
            continue
        outcome = decide(row[0], row[1])
        assert outcome.forward_to_agent is False
        assert outcome.sanitize_required is True
        assert outcome.escalation_immediate is True
        assert set(outcome.banned_verdicts) == set(ALL_VERDICTS)


def test_partial_rows_ban_benign_only_and_escalate_p1() -> None:
    """Ba hàng PARTIAL cấm `BENIGN`, escalate P1 chặn verdict (không tức thời)."""
    for row in EXPECTED_ROWS:
        if row[0] is not ProcessingState.PARTIAL:
            continue
        outcome = decide(row[0], row[1])
        assert outcome.banned_verdicts == (Verdict.BENIGN,)
        assert outcome.escalation is Escalation.P1
        assert outcome.escalation_immediate is False
        assert outcome.forward_to_agent is True


def test_complete_rows_have_no_pipeline_ban() -> None:
    """Hai hàng COMPLETE đầu không cấm verdict nào."""
    assert decide(ProcessingState.COMPLETE, DetectionState.DETECTED).banned_verdicts == ()
    assert (
        decide(ProcessingState.COMPLETE, DetectionState.NOT_DETECTED).banned_verdicts
        == ()
    )


def test_decide_rejects_values_outside_enums() -> None:
    """`decide` từ chối trạng thái không thuộc enum của contract."""
    with pytest.raises(ValueError):
        decide("COMPLETE", DetectionState.DETECTED)
    with pytest.raises(ValueError):
        decide(ProcessingState.COMPLETE, "DETECTED")


# --- Ánh xạ action ➔ pipeline_action --------------------------------------


def test_allow_maps_to_no_pipeline_action() -> None:
    """Ô `ALLOW` không có `pipeline_action` vì không phát hành bản ghi (§3.5.1)."""
    assert to_pipeline_action(PolicyAction.ALLOW) is None


@pytest.mark.parametrize("row", EXPECTED_ROWS[2:], ids=ROW_IDS[2:])
def test_non_allow_actions_map_into_pipeline_action_enum(
    row: tuple[object, ...],
) -> None:
    """Mọi action khác `ALLOW` ánh xạ vào enum `pipeline_action` §4.1."""
    assert to_pipeline_action(row[2]) is PipelineAction(str(row[2]))


# --- Ràng buộc verdict ----------------------------------------------------


def test_is_verdict_forbidden_reads_row_constraint() -> None:
    """Ràng buộc verdict đọc từ chính cột của ô, không suy diễn từ tên action."""
    partial = decide(ProcessingState.PARTIAL, DetectionState.NOT_DETECTED)
    assert is_verdict_forbidden(partial, Verdict.BENIGN)
    assert not is_verdict_forbidden(partial, Verdict.INCONCLUSIVE)

    failed = decide(ProcessingState.FAILED, DetectionState.NOT_DETECTED)
    assert all(is_verdict_forbidden(failed, verdict) for verdict in ALL_VERDICTS)

    clean = decide(ProcessingState.COMPLETE, DetectionState.DETECTED)
    assert not any(is_verdict_forbidden(clean, verdict) for verdict in ALL_VERDICTS)


# --- Tổng hợp detector (§3.5.1.1) -----------------------------------------

REQUIRED_TWO = ("YARA_STATIC", "TELEMETRY_ADAPTER")

AGGREGATION_CASES = [
    (
        "one-positive-only",
        [_positive("YARA_STATIC")],
        ("YARA_STATIC",),
        ProcessingState.COMPLETE,
        DetectionState.DETECTED,
    ),
    (
        "all-required-clean-negative",
        [_negative("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.COMPLETE,
        DetectionState.NOT_DETECTED,
    ),
    (
        "disagreement-positive-and-negative",
        [_positive("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.COMPLETE,
        DetectionState.INCONCLUSIVE,
    ),
    (
        "required-detector-errored",
        [_positive("YARA_STATIC"), _errored("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.COMPLETE,
        DetectionState.INCONCLUSIVE,
    ),
    (
        "required-detector-missing",
        [_positive("YARA_STATIC")],
        REQUIRED_TWO,
        ProcessingState.COMPLETE,
        DetectionState.INCONCLUSIVE,
    ),
    (
        "positive-without-provenance-is-not-valid",
        [_positive("YARA_STATIC", has_provenance=False)],
        ("YARA_STATIC",),
        ProcessingState.COMPLETE,
        DetectionState.INCONCLUSIVE,
    ),
    (
        "partial-all-required-clean-negative",
        [_negative("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.PARTIAL,
        DetectionState.NOT_DETECTED,
    ),
    (
        "failed-detector-error-without-positive",
        [_negative("YARA_STATIC"), _errored("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.FAILED,
        DetectionState.INCONCLUSIVE,
    ),
    (
        "failed-all-required-clean-negative",
        [_negative("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.FAILED,
        DetectionState.NOT_DETECTED,
    ),
    (
        "failed-positive-before-error",
        [_positive("YARA_CUCKOO"), _errored("TELEMETRY_ADAPTER")],
        ("YARA_CUCKOO", "TELEMETRY_ADAPTER"),
        ProcessingState.FAILED,
        DetectionState.DETECTED,
    ),
    (
        "empty-profile-with-negative-results",
        [_negative("YARA_STATIC")],
        (),
        ProcessingState.COMPLETE,
        DetectionState.INCONCLUSIVE,
    ),
]


@pytest.mark.parametrize(
    ("case", "results", "required", "coverage", "expected"),
    AGGREGATION_CASES,
    ids=[case[0] for case in AGGREGATION_CASES],
)
def test_aggregate_detection_state(
    case: str,
    results: list[dict],
    required: tuple[str, ...],
    coverage: ProcessingState,
    expected: DetectionState,
) -> None:
    """Quy tắc tổng hợp §3.5.1.1 trả đúng trạng thái cho từng tình huống."""
    assert aggregate_detection_state(results, required, coverage) is expected


def test_aggregate_defaults_to_complete_coverage() -> None:
    """Coverage mặc định là `COMPLETE` để caller chỉ quan tâm kết quả detector."""
    assert (
        aggregate_detection_state(
            [_negative("YARA_STATIC")], ("YARA_STATIC",)
        )
        is DetectionState.NOT_DETECTED
    )


def test_aggregate_rejects_result_without_name() -> None:
    """Mỗi kết quả detector phải có `name`; thiếu tên là lỗi lập trình."""
    with pytest.raises(ValueError):
        aggregate_detection_state([{"positive": True}], ("YARA_STATIC",))


# --- Cổng policy đầy đủ: cả 9 ô đều truy cập được -------------------------

REACHABILITY_CASES = [
    (
        "row1",
        [_positive("YARA_STATIC")],
        ("YARA_STATIC",),
        ProcessingState.COMPLETE,
        DetectionState.DETECTED,
    ),
    (
        "row2",
        [_negative("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.COMPLETE,
        DetectionState.NOT_DETECTED,
    ),
    (
        "row3",
        [_positive("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.COMPLETE,
        DetectionState.INCONCLUSIVE,
    ),
    (
        "row4",
        [_positive("YARA_STATIC")],
        ("YARA_STATIC",),
        ProcessingState.PARTIAL,
        DetectionState.DETECTED,
    ),
    (
        "row5",
        [_negative("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.PARTIAL,
        DetectionState.NOT_DETECTED,
    ),
    (
        "row6",
        [_positive("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.PARTIAL,
        DetectionState.INCONCLUSIVE,
    ),
    (
        "row7",
        [_positive("YARA_CUCKOO"), _errored("TELEMETRY_ADAPTER")],
        ("YARA_CUCKOO", "TELEMETRY_ADAPTER"),
        ProcessingState.FAILED,
        DetectionState.DETECTED,
    ),
    (
        "row8",
        [_negative("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.FAILED,
        DetectionState.NOT_DETECTED,
    ),
    (
        "row9",
        [_positive("YARA_STATIC"), _negative("TELEMETRY_ADAPTER")],
        REQUIRED_TWO,
        ProcessingState.FAILED,
        DetectionState.INCONCLUSIVE,
    ),
]


@pytest.mark.parametrize(
    ("case", "results", "required", "coverage", "detection_state"),
    REACHABILITY_CASES,
    ids=[case[0] for case in REACHABILITY_CASES],
)
def test_evaluate_policy_reaches_every_matrix_cell(
    case: str,
    results: list[dict],
    required: tuple[str, ...],
    coverage: ProcessingState,
    detection_state: DetectionState,
) -> None:
    """Từ kết quả detector thật, `evaluate_policy` rơi đúng ô mong đợi của ma trận."""
    evaluation = evaluate_policy(results, required, coverage)
    assert evaluation.detection_state is detection_state
    expected_row = next(
        row
        for row in EXPECTED_ROWS
        if row[0] is coverage and row[1] is detection_state
    )
    assert evaluation.outcome == _expected_outcome(expected_row)
