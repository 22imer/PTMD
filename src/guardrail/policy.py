"""Decision Policy Gate — ma trận 9 trạng thái & tổng hợp detector (spec v1.4.0 §3.5.1, §3.5.1.1).

Module này là phần policy của Lớp 4, thuần dữ liệu và không side effect: nhận
kết quả detector thô cùng `ProcessingState` của coverage, trả về quyết định gồm
pipeline action, chuyển tiếp context, bắt buộc sanitize, cờ trạng thái,
escalation và ràng buộc verdict. Việc dựng bản ghi evidence nằm ở
`guardrail.evidence`; `HARD_BLOCK` của Dispatcher Lớp 5 không có ô nào trong ma
trận nên không xuất hiện ở đây (xem §3.5.1, §5).

**Nguồn chân lý:** bảng 3×3 ở §3.5.1 được chép nguyên văn thành `DECISION_MATRIX`
(9 ô, không sinh tự động) và quy tắc tổng hợp §3.5.1.1 thành
`aggregate_detection_state`. Consumer đọc cờ từ trường `status_flags` của kết quả,
không suy diễn cờ từ tên action (§3.5.1.1).

**Thứ tự ưu tiên khi tổng hợp** (vì §3.5.1.1 mô tả ba trạng thái bằng văn xuôi,
thứ tự kiểm tra dưới đây được chốt tường minh):

1. *Bất đồng detector* — tồn tại đồng thời dương tính hợp lệ và âm tính hợp lệ:
   `INCONCLUSIVE` (a).
2. *Detector bắt buộc lỗi/không chạy được trong khi coverage chưa `FAILED`*:
   `INCONCLUSIVE` (b). "Không chạy được" gồm cả detector bắt buộc **thiếu hẳn**
   khỏi danh sách kết quả; một dương tính thiếu provenance không phải dương tính
   hợp lệ nên cũng tính là lỗi.
3. Có ≥1 dương tính hợp lệ: `DETECTED`.
4. Mọi detector bắt buộc của profile đều chạy sạch và âm tính: `NOT_DETECTED`.
5. Còn lại: `INCONCLUSIVE` (mặc định an toàn).

Hệ quả: `DETECTED`/`NOT_DETECTED` chỉ được tuyên bố khi bức tranh detector không
còn lỗ hổng chưa giải thích — (a) và (b) đứng trước cả dương tính, nên một dương
tính kèm detector bắt buộc lỗi (coverage chưa `FAILED`) rơi vào `INCONCLUSIVE`
(hàng 6 khi coverage `PARTIAL`), và vẫn được bảo toàn finding theo Finding
Preservation Rule. Khi coverage đã `FAILED`, điều kiện (b) không áp dụng (spec
viết "trong khi coverage chưa rơi vào `FAILED`"), nên dương tính đã phát hiện
trước lỗi vẫn cho `DETECTED` — đúng hàng 7. Profile rỗng (`required_detectors`
trống) **không** đủ cơ sở cho `NOT_DETECTED`: không có detector nào chạy sạch thì
trả `INCONCLUSIVE` thay vì `ALLOW` cho artifact chưa được quét.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NamedTuple, TypedDict

from guardrail.contracts import (
    DetectionState,
    PipelineAction,
    ProcessingState,
    StatusFlag,
    Verdict,
)

__all__ = [
    "DECISION_MATRIX",
    "DecisionOutcome",
    "DetectorResult",
    "Escalation",
    "PolicyAction",
    "PolicyEvaluation",
    "aggregate_detection_state",
    "decide",
    "evaluate_policy",
    "is_verdict_forbidden",
    "to_pipeline_action",
]


# --- Vocabulary của ma trận §3.5.1 ----------------------------------------


class Escalation(StrEnum):
    """Mức escalation ở cột "Escalation" của ma trận §3.5.1."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class PolicyAction(StrEnum):
    """Cột "Pipeline Action" của ma trận §3.5.1, gồm cả `ALLOW`.

    `contracts.PipelineAction` cố ý không có `ALLOW` vì nhánh đó không phát hành
    bản ghi evidence; policy vẫn phải biểu diễn được ô 2 của ma trận nên giữ
    `ALLOW` ở đây và ánh xạ sang `None` bằng :func:`to_pipeline_action`.
    `HARD_BLOCK` không thuộc ma trận (Dispatcher Lớp 5) nên không có mặt.
    """

    ALLOW = "ALLOW"
    TAG_AS_EVIDENCE = "TAG_AS_EVIDENCE"
    CAUTIOUS_QUARANTINE = "CAUTIOUS_QUARANTINE"
    ESCALATE_AND_INCONCLUSIVE = "ESCALATE_AND_INCONCLUSIVE"
    PIPELINE_ABSTENTION = "PIPELINE_ABSTENTION"


class DecisionOutcome(NamedTuple):
    """Kết quả một ô của ma trận §3.5.1.

    - ``pipeline_action``: action của ô; `ALLOW` nghĩa là không phát hành bản ghi.
    - ``forward_to_agent``: cột "Chuyển tiếp Context".
    - ``sanitize_required``: cột "Bắt buộc Sanitize".
    - ``status_flags``: cột "Cờ trạng thái" (rỗng khi cột không quy định cờ).
    - ``escalation``: `None` khi cột "Escalation" ghi "Không".
    - ``escalation_immediate``: phân biệt "P1 chặn verdict" (hàng 4–6, `False`)
      với "P1 tức thời" (hàng 7–9, `True`).
    - ``banned_verdicts``: cột "Ràng buộc Verdict" — rỗng nghĩa là không cấm.
    """

    pipeline_action: PolicyAction
    forward_to_agent: bool
    sanitize_required: bool
    status_flags: tuple[StatusFlag, ...]
    escalation: Escalation | None
    escalation_immediate: bool
    banned_verdicts: tuple[Verdict, ...]


# --- Ma trận 3×3 (spec §3.5.1) --------------------------------------------

_ALL_VERDICTS: tuple[Verdict, ...] = (
    Verdict.MALICIOUS,
    Verdict.SUSPICIOUS,
    Verdict.BENIGN,
    Verdict.INCONCLUSIVE,
)
_TRUNCATED: tuple[StatusFlag, ...] = (StatusFlag.TRUNCATED_ARTIFACT_FLAG,)
_DISAGREEMENT: tuple[StatusFlag, ...] = (StatusFlag.DETECTOR_DISAGREEMENT,)

#: Chép nguyên văn 9 hàng của bảng quyết định §3.5.1.
DECISION_MATRIX: dict[tuple[ProcessingState, DetectionState], DecisionOutcome] = {
    # 1. COMPLETE + DETECTED
    (ProcessingState.COMPLETE, DetectionState.DETECTED): DecisionOutcome(
        pipeline_action=PolicyAction.TAG_AS_EVIDENCE,
        forward_to_agent=True,
        sanitize_required=True,
        status_flags=(),
        escalation=Escalation.P3,
        escalation_immediate=False,
        banned_verdicts=(),
    ),
    # 2. COMPLETE + NOT_DETECTED
    (ProcessingState.COMPLETE, DetectionState.NOT_DETECTED): DecisionOutcome(
        pipeline_action=PolicyAction.ALLOW,
        forward_to_agent=True,
        sanitize_required=False,
        status_flags=(),
        escalation=None,
        escalation_immediate=False,
        banned_verdicts=(),
    ),
    # 3. COMPLETE + INCONCLUSIVE
    (ProcessingState.COMPLETE, DetectionState.INCONCLUSIVE): DecisionOutcome(
        pipeline_action=PolicyAction.CAUTIOUS_QUARANTINE,
        forward_to_agent=True,
        sanitize_required=True,
        status_flags=_DISAGREEMENT,
        escalation=Escalation.P2,
        escalation_immediate=False,
        banned_verdicts=(Verdict.BENIGN,),
    ),
    # 4. PARTIAL + DETECTED
    (ProcessingState.PARTIAL, DetectionState.DETECTED): DecisionOutcome(
        pipeline_action=PolicyAction.ESCALATE_AND_INCONCLUSIVE,
        forward_to_agent=True,
        sanitize_required=True,
        status_flags=_TRUNCATED,
        escalation=Escalation.P1,
        escalation_immediate=False,
        banned_verdicts=(Verdict.BENIGN,),
    ),
    # 5. PARTIAL + NOT_DETECTED
    (ProcessingState.PARTIAL, DetectionState.NOT_DETECTED): DecisionOutcome(
        pipeline_action=PolicyAction.ESCALATE_AND_INCONCLUSIVE,
        forward_to_agent=True,
        sanitize_required=True,
        status_flags=_TRUNCATED,
        escalation=Escalation.P1,
        escalation_immediate=False,
        banned_verdicts=(Verdict.BENIGN,),
    ),
    # 6. PARTIAL + INCONCLUSIVE
    (ProcessingState.PARTIAL, DetectionState.INCONCLUSIVE): DecisionOutcome(
        pipeline_action=PolicyAction.ESCALATE_AND_INCONCLUSIVE,
        forward_to_agent=True,
        sanitize_required=True,
        status_flags=(StatusFlag.TRUNCATED_ARTIFACT_FLAG, StatusFlag.DETECTOR_DISAGREEMENT),
        escalation=Escalation.P1,
        escalation_immediate=False,
        banned_verdicts=(Verdict.BENIGN,),
    ),
    # 7. FAILED + DETECTED
    (ProcessingState.FAILED, DetectionState.DETECTED): DecisionOutcome(
        pipeline_action=PolicyAction.PIPELINE_ABSTENTION,
        forward_to_agent=False,
        sanitize_required=True,
        status_flags=_TRUNCATED,
        escalation=Escalation.P1,
        escalation_immediate=True,
        banned_verdicts=_ALL_VERDICTS,
    ),
    # 8. FAILED + NOT_DETECTED
    (ProcessingState.FAILED, DetectionState.NOT_DETECTED): DecisionOutcome(
        pipeline_action=PolicyAction.PIPELINE_ABSTENTION,
        forward_to_agent=False,
        sanitize_required=True,
        status_flags=_TRUNCATED,
        escalation=Escalation.P1,
        escalation_immediate=True,
        banned_verdicts=_ALL_VERDICTS,
    ),
    # 9. FAILED + INCONCLUSIVE
    (ProcessingState.FAILED, DetectionState.INCONCLUSIVE): DecisionOutcome(
        pipeline_action=PolicyAction.PIPELINE_ABSTENTION,
        forward_to_agent=False,
        sanitize_required=True,
        status_flags=_TRUNCATED,
        escalation=Escalation.P1,
        escalation_immediate=True,
        banned_verdicts=_ALL_VERDICTS,
    ),
}


# --- Tổng hợp kết quả detector (spec §3.5.1.1) ----------------------------


class DetectorResult(TypedDict, total=False):
    """Kết quả một detector cho phạm vi artifact đang xét.

    ``name`` và ``positive`` là bắt buộc trên thực tế (thiếu ``name`` bị từ chối,
    thiếu ``positive`` hiểu là âm tính). ``has_provenance`` mặc định `True`; đặt
    `False` cho một dương tính không kèm provenance đầy đủ — khi đó kết quả không
    phải dương tính hợp lệ và bị coi như detector lỗi.
    """

    name: str
    positive: bool
    errored: bool
    score: float
    has_provenance: bool


class PolicyEvaluation(NamedTuple):
    """Kết quả cổng policy: trạng thái detector tổng hợp và ô ma trận tương ứng."""

    detection_state: DetectionState
    outcome: DecisionOutcome


def _detector_name(result: DetectorResult) -> str:
    name = result.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("mỗi DetectorResult phải có 'name' là chuỗi khác rỗng")
    return name


def _is_errored(result: DetectorResult) -> bool:
    """Detector lỗi: tự khai `errored`, hoặc dương tính không có provenance hợp lệ.

    Dương tính thiếu provenance không dùng được cho `DETECTED` (§3.5.1.1 yêu cầu
    "kèm provenance đầy đủ") nên tính là lỗi của detector, không âm thầm bỏ qua.
    """
    if result.get("errored", False):
        return True
    return bool(result.get("positive", False)) and not result.get("has_provenance", True)


def _is_valid_positive(result: DetectorResult) -> bool:
    return bool(result.get("positive", False)) and not _is_errored(result)


def _is_valid_negative(result: DetectorResult) -> bool:
    return not result.get("positive", False) and not result.get("errored", False)


def aggregate_detection_state(
    results: list[DetectorResult] | tuple[DetectorResult, ...],
    required_detectors: list[str] | tuple[str, ...],
    coverage: ProcessingState = ProcessingState.COMPLETE,
) -> DetectionState:
    """Tổng hợp kết quả detector thành `DetectionState` (spec §3.5.1.1).

    ``required_detectors`` là profile detector bắt buộc do caller truyền vào
    (YARA static/cuckoo, Telemetry Adapter, Prompt Guard — tuỳ profile); policy
    không tự suy luận danh sách này. Thứ tự kiểm tra theo docstring module:
    bất đồng ➔ detector bắt buộc lỗi (coverage chưa `FAILED`) ➔ dương tính hợp lệ
    ➔ toàn bộ detector bắt buộc chạy sạch âm tính ➔ `INCONCLUSIVE` mặc định.
    """
    required = tuple(required_detectors)
    by_name: dict[str, DetectorResult] = {}
    for result in results:
        by_name[_detector_name(result)] = result

    valid_positives = [r for r in results if _is_valid_positive(r)]
    valid_negatives = [r for r in results if _is_valid_negative(r)]

    if valid_positives and valid_negatives:
        return DetectionState.INCONCLUSIVE

    missing_or_errored = [
        name
        for name in required
        if name not in by_name or _is_errored(by_name[name])
    ]
    if missing_or_errored and coverage is not ProcessingState.FAILED:
        return DetectionState.INCONCLUSIVE

    if valid_positives:
        return DetectionState.DETECTED

    all_required_clean = bool(required) and all(
        name in by_name and _is_valid_negative(by_name[name]) for name in required
    )
    if all_required_clean:
        return DetectionState.NOT_DETECTED

    return DetectionState.INCONCLUSIVE


# --- Cổng quyết định ------------------------------------------------------


def decide(
    processing_state: ProcessingState, detection_state: DetectionState
) -> DecisionOutcome:
    """Tra ma trận 3×3 §3.5.1 cho một cặp trạng thái."""
    if not isinstance(processing_state, ProcessingState):
        raise ValueError(f"processing_state không hợp lệ: {processing_state!r}")
    if not isinstance(detection_state, DetectionState):
        raise ValueError(f"detection_state không hợp lệ: {detection_state!r}")
    return DECISION_MATRIX[(processing_state, detection_state)]


def evaluate_policy(
    results: list[DetectorResult] | tuple[DetectorResult, ...],
    required_detectors: list[str] | tuple[str, ...],
    processing_state: ProcessingState,
) -> PolicyEvaluation:
    """Cổng policy đầy đủ: tổng hợp detector rồi tra ma trận."""
    detection_state = aggregate_detection_state(results, required_detectors, processing_state)
    return PolicyEvaluation(detection_state, decide(processing_state, detection_state))


def to_pipeline_action(action: PolicyAction) -> PipelineAction | None:
    """Ánh xạ action của ma trận sang enum `pipeline_action` §4.1.

    `ALLOW` không sinh bản ghi evidence nên trả `None` (xem §3.5.1, ánh xạ
    Pipeline Action ➔ Evidence Decision, và docstring `PolicyAction`).
    """
    if action is PolicyAction.ALLOW:
        return None
    return PipelineAction(str(action))


def is_verdict_forbidden(outcome: DecisionOutcome, verdict: Verdict) -> bool:
    """`True` nếu cột "Ràng buộc Verdict" của ô cấm `verdict`."""
    return verdict in outcome.banned_verdicts
