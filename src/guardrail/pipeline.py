"""E2E pipeline wiring — Module 4 tích hợp (spec §3.5, §3.5.1, §3.5.2, §3.6, §4).

Luồng tất định, không mạng, không model thật:

    telemetry/extraction → normalization → YARA (+ Prompt Guard tuỳ chọn)
      → policy gate (ma trận 3×3) → evidence emission
      → context Spotlighting → agent (stub/simulated) → report validation/fallback
      → Canary Token Verifier → kết quả cuối

Detector profile (``required_detectors``) là **phạm vi artifact thực tế**, không
phải danh sách cứng: ``TELEMETRY_ADAPTER`` (nhánh động: YARA trên chuỗi telemetry
đã chuẩn hoá) và ``META_PROMPT_GUARD`` luôn bắt buộc; ``YARA_STATIC`` chỉ vào
profile khi caller cấp ``artifact_bytes``; ``YARA_CUCKOO`` chỉ khi caller cấp
``cape_report_path``. Detector bắt buộc không chạy được (ví dụ Prompt Guard không
có backend) được ghi là ``errored`` — theo §3.5.1.1 (b) kết quả là
``INCONCLUSIVE``, không phải "âm tính".

Agent là một callable nhận :class:`guardrail.report.AgentRequest`; mặc định dùng
:class:`SimulatedAgent` (tất định, suy verdict từ detection state + evidence) để
smoke E2E chạy được mà không cần LLM. Truyền ``agent_stub`` để mô phỏng nhánh lỗi
(re-ask/fallback).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import NamedTuple

from guardrail.capa_projection import CapaProjectionError, project_capabilities
from guardrail.context import (
    DEFAULT_MODEL_ID,
    SpotlightedPayload,
    build_chat_payload,
    summarize_finding,
)
from guardrail.contracts import (
    DetectionSource,
    DetectionState,
    DetectorName,
    EvidenceRecord,
    MitreAtlasMapping,
    OwaspLlmMapping,
    ProcessingState,
    ProvenanceType,
    ReportStatus,
    StatusFlag,
    Verdict,
)
from guardrail.evidence import (
    SHA256_PATTERN,
    EvidenceSeed,
    build_provenance,
    emit_policy_evidence,
)
from guardrail.evidence import (
    Finding as EvidenceFinding,
)
from guardrail.extraction import MAX_STRINGS, extract_strings
from guardrail.malware_analysis import (
    LayaMalwareAnalyzer,
    MalwareAnalysisResult,
    is_laya_eligible,
    validate_malware_analysis,
)
from guardrail.malware_facts import FactsOutcome, extract_malware_facts
from guardrail.normalization import (
    NormalizationEngine,
    NormalizedText,
    load_confusables_map,
)
from guardrail.policy import (
    DecisionOutcome,
    DetectorResult,
    PolicyAction,
    evaluate_policy,
)
from guardrail.prompt_guard import (
    LABEL_JAILBREAK,
    PromptGuardBackend,
    PromptGuardConfig,
    PromptGuardError,
    PromptGuardService,
    is_promptware,
)
from guardrail.report import (
    MAX_RE_ASKS,
    AgentRequest,
    ReAskController,
    ReportOutcome,
    ReportValidator,
    build_fallback_report,
    validate_final_report,
)
from guardrail.runtime import (
    CanaryVerdict,
    CanaryVerifier,
    DispatcherStore,
    ReadOnlyDispatcher,
)
from guardrail.telemetry import TelemetryIngestionAdapter
from guardrail.yara_scanner import Finding as YaraFinding
from guardrail.yara_scanner import YaraScanner

__all__ = [
    "ATLAS_OWASP_MAPPINGS",
    "ATLAS_TECHNIQUE_NAMES",
    "PipelineError",
    "PipelineResult",
    "SimulatedAgent",
    "run_pipeline",
]

#: Tên ATLAS → tên kỹ thuật (snapshot 2026.09) cho các mã pipeline có thể sinh.
#: Mã ngoài bảng dùng sentinel no-mapping §4.1 thay vì bịa tên.
ATLAS_TECHNIQUE_NAMES: dict[str, str] = {
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0034": "Cost Harvesting",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0043.001": "Craft Adversarial Data: Black-Box Optimization",
    "AML.T0048": "External Harms",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0015": "Evade AI Model",
}

#: Mã ATLAS → OWASP LLM mapping (spec §5).
ATLAS_OWASP_MAPPINGS: dict[str, OwaspLlmMapping] = {
    "AML.T0051.001": OwaspLlmMapping.PROMPT_INJECTION,
    "AML.T0034": OwaspLlmMapping.NO_DIRECT_MAPPING,
    "AML.T0043": OwaspLlmMapping.PROMPT_INJECTION,
    "AML.T0043.001": OwaspLlmMapping.PROMPT_INJECTION,
    "AML.T0048": OwaspLlmMapping.NO_DIRECT_MAPPING,
    "AML.T0051": OwaspLlmMapping.PROMPT_INJECTION,
    "AML.T0053": OwaspLlmMapping.EXCESSIVE_AGENCY,
    "AML.T0054": OwaspLlmMapping.PROMPT_INJECTION,
    "AML.T0056": OwaspLlmMapping.SYSTEM_PROMPT_LEAKAGE,
    "AML.T0057": OwaspLlmMapping.SYSTEM_PROMPT_LEAKAGE,
    "AML.T0015": OwaspLlmMapping.PROMPT_INJECTION,
}

_YARA_RULE_VERSION_FALLBACK = "1.4.0"
_PIPELINE_RECORD_VERSION = "pipeline-v1.4.0"
_COMPLETE = str(ReportStatus.COMPLETE)
_NO_MAPPING_REASON = (
    "Không có ánh xạ ATLAS cho mã nguồn của detector trong bảng snapshot 2026.09"
)


class PipelineError(RuntimeError):
    """Lỗi bất biến nội bộ của pipeline (không phải lỗi dữ liệu đầu vào)."""


class PipelineResult(NamedTuple):
    """Kết quả một lần chạy E2E, đủ để tái lập và kiểm từng tầng.

    ``report`` là report cuối (hợp lệ hoặc fallback abstention). Khi
    ``agent_invoked=False`` (hàng FAILED của §3.5.1) thì ``payload`` là ``None``:
    pipeline không hỏi agent verdict.
    """

    artifact_sha256: str
    processing_state: ProcessingState
    detection_state: DetectionState
    decision: DecisionOutcome
    detector_results: list[DetectorResult]
    required_detectors: tuple[str, ...]
    capabilities: list[dict[str, str]]
    evidence: list[EvidenceRecord]
    payload: SpotlightedPayload | None
    agent_invoked: bool
    report: Mapping[str, object]
    report_outcome: ReportOutcome
    canary: CanaryVerdict | None
    limitations: list[str]
    malware_analysis: MalwareAnalysisResult | None

    @property
    def report_status(self) -> object:
        return self.report.get("report_status")

    @property
    def verdict(self) -> object:
        assessment = self.report.get("threat_assessment")
        return assessment.get("verdict") if isinstance(assessment, Mapping) else None

    def as_dict(self) -> dict[str, object]:
        """Bản JSON-hoá tất định của toàn bộ kết quả (kể cả payload và evidence)."""
        decision = self.decision
        serialized: dict[str, object] = {
            "artifact_sha256": self.artifact_sha256,
            "processing_state": str(self.processing_state),
            "detection_state": str(self.detection_state),
            "decision": {
                "pipeline_action": str(decision.pipeline_action),
                "forward_to_agent": decision.forward_to_agent,
                "sanitize_required": decision.sanitize_required,
                "status_flags": [str(flag) for flag in decision.status_flags],
                "escalation": None if decision.escalation is None else str(decision.escalation),
                "escalation_immediate": decision.escalation_immediate,
                "banned_verdicts": [str(verdict) for verdict in decision.banned_verdicts],
            },
            "detector_results": [dict(result) for result in self.detector_results],
            "required_detectors": list(self.required_detectors),
            "capabilities": [dict(row) for row in self.capabilities],
            "evidence": [dict(record) for record in self.evidence],
            "payload": None if self.payload is None else self.payload.payload,
            "agent_invoked": self.agent_invoked,
            "report": dict(self.report),
            "report_outcome": {
                "attempts": self.report_outcome.attempts,
                "errors": list(self.report_outcome.errors),
                "abstained": self.report_outcome.abstained,
            },
            "canary": None if self.canary is None else _canary_dict(self.canary),
            "limitations": list(self.limitations),
        }
        if self.malware_analysis is not None:
            serialized["malware_analysis"] = dict(self.malware_analysis)
        return serialized

    def to_json(self) -> str:
        """JSON khóa sắp xếp — hai lần chạy cùng đầu vào cho cùng chuỗi byte."""
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=2, sort_keys=True)


def _canary_dict(verdict: CanaryVerdict) -> dict[str, object]:
    return {
        "leaked": verdict.leaked,
        "released": verdict.released,
        "output": verdict.output,
        "hits": [
            {"token": hit.token, "locator": hit.locator, "kind": hit.kind}
            for hit in verdict.hits
        ],
        "evidence": [dict(record) for record in verdict.evidence],
    }


def _empty_malware_facts() -> FactsOutcome:
    return FactsOutcome(
        facts=(),
        links=(),
        coverage=ProcessingState.FAILED,
        errors=(),
        behavior_available=False,
        network_available=False,
        capa_available=False,
    )


def _validate_laya_companion(
    result: MalwareAnalysisResult,
    facts: FactsOutcome,
    analyzer: LayaMalwareAnalyzer,
    artifact_sha256: str,
) -> None:
    errors = validate_malware_analysis(
        result,
        facts=facts,
        workflow=analyzer.workflow,
        artifact_sha256=artifact_sha256,
    )
    if errors:
        raise PipelineError("malware_analysis companion failed schema or provenance validation")


def _laya_companion(
    analyzer: LayaMalwareAnalyzer,
    facts: FactsOutcome | None,
    *,
    source_binding_failed: bool,
    artifact_sha256: str,
    processing_state: ProcessingState,
    detection_state: DetectionState,
    outcome: DecisionOutcome,
) -> MalwareAnalysisResult:
    if source_binding_failed or facts is None:
        result = analyzer.blocked(
            None,
            artifact_sha256=artifact_sha256,
            reason="ARTIFACT_MISMATCH",
            limitations=["CAPE/CAPA/artifact SHA-256 binding failed; Laya was not invoked."],
        )
        validation_facts = _empty_malware_facts()
    elif not is_laya_eligible(processing_state, detection_state, outcome, facts.coverage):
        validation_facts = facts
        policy_is_clean = (
            processing_state is ProcessingState.COMPLETE
            and detection_state is DetectionState.NOT_DETECTED
            and outcome.pipeline_action is PolicyAction.ALLOW
        )
        if policy_is_clean:
            result = analyzer.blocked(
                facts,
                artifact_sha256=artifact_sha256,
                reason="FACTS_INCOMPLETE",
                limitations=["Malware fact coverage is incomplete; Laya was not invoked."],
            )
        else:
            result = analyzer.blocked(
                facts,
                artifact_sha256=artifact_sha256,
                reason="GUARDRAIL_NOT_CLEAN",
                limitations=["Guardrail policy or detector coverage blocked the Laya handoff."],
            )
    else:
        validation_facts = facts
        result = analyzer.analyze(facts, artifact_sha256=artifact_sha256)
        # Readiness is the verified handoff gate, not a model verdict.
        result["ready_for_ai"] = True
    _validate_laya_companion(result, validation_facts, analyzer, artifact_sha256)
    return result


def _atlas_mappings(code: object) -> list[MitreAtlasMapping]:
    """Ánh xạ mã ATLAS của rule/meta sang block §4.1 (sentinel khi không có bảng)."""
    if isinstance(code, str):
        codes = [part.strip() for part in code.replace(",", " ").split() if part.strip()]
    else:
        codes = []
    mappings: list[MitreAtlasMapping] = [
        MitreAtlasMapping(technique_id=item, technique_name=ATLAS_TECHNIQUE_NAMES[item])
        for item in codes
        if item in ATLAS_TECHNIQUE_NAMES
    ]
    if mappings:
        return mappings
    return [
        MitreAtlasMapping(
            technique_id="No direct mapping",
            technique_name="No direct mapping",
            no_mapping_reason=_NO_MAPPING_REASON,
        )
    ]


def _owasp_mapping(code: object) -> OwaspLlmMapping:
    if isinstance(code, str):
        for part in code.replace(",", " ").split():
            mapping = ATLAS_OWASP_MAPPINGS.get(part.strip())
            if mapping is not None:
                return mapping
    return OwaspLlmMapping.NO_DIRECT_MAPPING


def _yara_finding_to_evidence(
    finding: YaraFinding,
    *,
    detector_name: DetectorName,
    interpretation_summary: str,
) -> EvidenceFinding:
    return EvidenceFinding(
        detector_name=detector_name,
        rule_or_model_version=finding.rule_version or _YARA_RULE_VERSION_FALLBACK,
        score=1.0,
        detection_source=finding.detection_source,
        provenance=finding.provenance,
        interpretation_summary=interpretation_summary,
        transform_chain=list(finding.transform_chain),
        mitre_atlas_mappings=_atlas_mappings(finding.mitre_atlas),
        owasp_llm_mapping=_owasp_mapping(finding.mitre_atlas),
        confidence_score=0.9,
    )


def _dedupe_yara_findings(findings: Sequence[YaraFinding]) -> list[YaraFinding]:
    """Gộp finding cùng rule: một bản ghi/rule, hợp nhất transform_chain theo thứ tự."""
    seen: dict[str, int] = {}
    merged: list[YaraFinding] = []
    for finding in findings:
        key = f"{finding.detector_name}:{finding.rule}"
        if key in seen:
            index = seen[key]
            existing = merged[index]
            chain = list(existing.transform_chain)
            for step in finding.transform_chain:
                if step not in chain:
                    chain.append(step)
            merged[index] = existing._replace(transform_chain=chain)
            continue
        seen[key] = len(merged)
        merged.append(finding)
    return merged


def _detector_result(
    name: DetectorName,
    *,
    positive: bool,
    score: float = 0.0,
    errored: bool = False,
    has_provenance: bool = True,
) -> DetectorResult:
    return DetectorResult(
        name=str(name),
        positive=positive,
        errored=errored,
        score=score,
        has_provenance=has_provenance,
    )


class SimulatedAgent:
    """Agent stub tất định: suy verdict từ detection state + evidence.

    Dùng cho smoke E2E khi không có LLM. Không truy cập mạng, không đọc file,
    không dùng thời gian. Verdict bị cấm bởi ô ma trận được thay bằng
    ``INCONCLUSIVE`` (không bao giờ hạ xuống ``BENIGN``).
    """

    def __init__(
        self,
        *,
        artifact_sha256: str,
        file_type: str,
        packer_detected: str,
        capabilities: Sequence[Mapping[str, str]],
        evidence: Sequence[EvidenceRecord],
        outcome: DecisionOutcome,
        status_flags: Sequence[StatusFlag | str] = (),
    ) -> None:
        self.artifact_sha256 = artifact_sha256
        self.file_type = file_type
        self.packer_detected = packer_detected
        self.capabilities = list(capabilities)
        self.evidence = list(evidence)
        self.outcome = outcome
        self.status_flags = [str(flag) for flag in status_flags]

    def _verdict(self) -> Verdict:
        if self.evidence:
            candidate = Verdict.MALICIOUS if self.capabilities else Verdict.SUSPICIOUS
        else:
            candidate = Verdict.BENIGN
        if candidate in self.outcome.banned_verdicts:
            return Verdict.INCONCLUSIVE
        return candidate

    def __call__(self, request: AgentRequest) -> Mapping[str, object]:
        verdict = self._verdict()
        if verdict is Verdict.MALICIOUS:
            score, confidence = 8, 0.9
        elif verdict is Verdict.SUSPICIOUS:
            score, confidence = 5, 0.7
        elif verdict is Verdict.BENIGN:
            score, confidence = 1, 0.6
        else:
            score, confidence = None, None

        attacks = [summarize_finding(record) for record in self.evidence]
        capabilities: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for row in self.capabilities:
            key = (
                str(row.get("tactic", "")),
                str(row.get("technique_id", "")),
                str(row.get("technique_name", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            capabilities.append(
                {"tactic": key[0], "technique_id": key[1], "technique_name": key[2]}
            )

        report: dict[str, object] = {
            "report_status": str(_COMPLETE),
            "sample_metadata": {
                "sha256": self.artifact_sha256,
                "file_type": self.file_type,
                "packer_detected": self.packer_detected,
            },
            "threat_assessment": {
                "verdict": str(verdict),
                "threat_score": score,
                "confidence": confidence,
            },
            "mitre_attack_capabilities": capabilities,
            "adversarial_evasion_findings": {
                "prompt_injection_detected": bool(attacks),
                "evasion_attempts": attacks,
            },
            "executive_summary": (
                f"Simulated agent: {len(self.evidence)} bản ghi đối kháng, "
                f"{len(capabilities)} capability ATT&CK; kết luận {verdict}."
            ),
            "recommended_actions": [
                "Đối chiếu evidence_id trong báo cáo với kho evidence của artifact.",
                "Chuyển analyst người xem xét khi verdict không phải BENIGN.",
            ],
        }
        if self.status_flags:
            report["status_flags"] = list(self.status_flags)
        return report


def _derive_file_type(cape_report: object) -> str:
    if isinstance(cape_report, Mapping):
        target = cape_report.get("target")
        if isinstance(target, Mapping):
            file_info = target.get("file")
            if isinstance(file_info, Mapping):
                value = file_info.get("type")
                if isinstance(value, str) and value:
                    return value
    return "unknown"


def _coverage_states(states: Iterable[ProcessingState]) -> ProcessingState:
    states = list(states)
    if any(state is ProcessingState.FAILED for state in states):
        return ProcessingState.FAILED
    if any(state is ProcessingState.PARTIAL for state in states):
        return ProcessingState.PARTIAL
    return ProcessingState.COMPLETE


def _coverage_seed(
    detector_results: Sequence[DetectorResult],
    provenance: Mapping[str, object],
    interpretation_summary: str,
) -> EvidenceSeed:
    methods = [
        {
            "detector_name": result["name"],
            "rule_or_model_version": _PIPELINE_RECORD_VERSION,
            "score": float(result.get("score", 0.0)),
        }
        for result in detector_results
    ]
    if not methods:
        methods = [
            {
                "detector_name": str(DetectorName.TELEMETRY_ADAPTER),
                "rule_or_model_version": _PIPELINE_RECORD_VERSION,
                "score": 0.0,
            }
        ]
    return EvidenceSeed(
        detection_methods=methods,
        detection_source=DetectionSource.SANDBOX_API_LOG,
        provenance=build_provenance(
            ProvenanceType.JSON_LOG_POINTER,
            locator=str(provenance.get("locator", "/behavior")),
            section_or_pid=None,
        ),
        interpretation_summary=interpretation_summary,
        transform_chain=[],
        mitre_atlas_mappings=_atlas_mappings(None),
        owasp_llm_mapping=OwaspLlmMapping.NO_DIRECT_MAPPING,
        confidence_score=0.0,
    )


def _prompt_guard_findings(
    service: PromptGuardService,
    inputs: Sequence[tuple[NormalizedText, DetectionSource]],
    *,
    yara_flagged_texts: frozenset[str] = frozenset(),
    target_entity_is_llm: bool = False,
) -> tuple[list[EvidenceFinding], bool, ProcessingState, int]:
    """Classify unique normalized text while retaining every source/provenance pair."""
    sources_by_text: dict[str, list[tuple[NormalizedText, DetectionSource]]] = {}
    for item, source in inputs:
        sources_by_text.setdefault(item.normalized_string, []).append((item, source))

    classification = service.classify_batch(list(sources_by_text))
    findings: list[EvidenceFinding] = []
    seen: set[str] = set()
    missing_provenance = False
    filtered_non_promptware = 0
    for score in classification.scores:
        if not score.detected or score.text in seen:
            continue
        seen.add(score.text)
        source_items = sources_by_text.get(score.text)
        if not source_items:
            missing_provenance = True
            continue
        if not is_promptware(
            model_detected=True,
            target_entity_is_llm=target_entity_is_llm,
            instruction_override_context=score.text in yara_flagged_texts,
        ):
            filtered_non_promptware += 1
            continue
        label = LABEL_JAILBREAK if score.predicted_label == LABEL_JAILBREAK else "INJECTION"
        code = "AML.T0054" if label == LABEL_JAILBREAK else "AML.T0051.001"
        for item, source in source_items:
            findings.append(
                EvidenceFinding(
                    detector_name=DetectorName.META_PROMPT_GUARD,
                    rule_or_model_version=classification.revision,
                    score=score.detection_score,
                    detection_source=source,
                    provenance=item.provenance,
                    interpretation_summary=(
                        f"Prompt Guard phân loại {label} (score={score.detection_score:.3f}) "
                        f"trên chuỗi đã chuẩn hoá từ {source}."
                    ),
                    transform_chain=list(item.transform_chain),
                    mitre_atlas_mappings=_atlas_mappings(code),
                    owasp_llm_mapping=_owasp_mapping(code),
                    confidence_score=score.detection_score,
                )
            )
    errored = classification.detected and missing_provenance
    return findings, errored, classification.coverage, filtered_non_promptware


def run_pipeline(  # noqa: PLR0913 - E2E wiring cần nhiều tham số cấu hình rõ ràng
    cape_report: object,
    *,
    artifact_sha256: str,
    backend: PromptGuardBackend | None = None,
    agent_stub: Callable[[AgentRequest], object] | None = None,
    malware_analyzer: LayaMalwareAnalyzer | None = None,
    capa_report: object | None = None,
    artifact_bytes: bytes | None = None,
    cape_report_path: str | Path | None = None,
    dispatcher_store: DispatcherStore | None = None,
    scanner: YaraScanner | None = None,
    canaries: Sequence[str] = (),
    model: str = DEFAULT_MODEL_ID,
    year: int = 2026,
    first_evidence_sequence: int = 1,
    max_re_asks: int = MAX_RE_ASKS,
    prompt_guard_config: PromptGuardConfig | None = None,
    prompt_guard_budget: int = MAX_STRINGS,
    prompt_guard_target_entity_is_llm: bool = False,
    file_type: str | None = None,
    packer_detected: str = "not detected",
) -> PipelineResult:
    """Chạy E2E guardrail trên một CAPEv2 report đã parse (không mạng, tất định).

    Args:
        cape_report: CAPEv2 JSON đã parse (object).
        artifact_sha256: hash artifact (64 hex) — dùng cho evidence và report.
        backend: backend Prompt Guard (stub/transformers). ``None`` ⇒ detector
            ``META_PROMPT_GUARD`` ghi ``errored`` (model gated) ⇒ ``INCONCLUSIVE``.
        agent_stub: callable nhận ``AgentRequest`` trả report; mặc định
            :class:`SimulatedAgent`.
        malware_analyzer: opt-in passive consumer; disabled by default and
            mutually exclusive with ``agent_stub``.
        capa_report: output ``capa -j`` đã parse cho nhánh capability (tuỳ chọn).
        artifact_bytes: bytes artifact cho nhánh static (extraction → normalization
            → YARA). ``None`` ⇒ static không nằm trong profile.
        cape_report_path: đường dẫn report cho module Cuckoo. ``None`` ⇒ Cuckoo
            không nằm trong profile.
        dispatcher_store: store cho Read-Only Dispatcher (cấp cho agent qua
            ``AgentRequest.tools``).
        scanner: YARA scanner dùng cho mọi nhánh quét; ``None`` ⇒ ``YaraScanner()``
            mặc định. Cho phép test bơm scanner lỗi để chạm nhánh coverage FAILED.
        canaries: canary đã cấp; đưa vào kênh system và kiểm ở output cuối.
        model: model id trong payload.
        year / first_evidence_sequence: cấp ``evidence_id`` tất định.
        max_re_asks: số lần re-ask tối đa (spec §3.6: 2).
        prompt_guard_config: cấu hình Prompt Guard; mặc định lấy từ file ghim.
        prompt_guard_budget: trần số chuỗi chuẩn hoá duy nhất gửi cho Prompt Guard,
            dùng chung giữa telemetry và strings trích từ artifact.
        prompt_guard_target_entity_is_llm: biến ngữ cảnh ``TargetEntityIsLLM`` của
            predicate §3.4 — caller khẳng định chuỗi đầu vào được chuyển vào context
            LLM thì truyền ``True``; mặc định ``False``. ``InstructionOverrideContext``
            tự suy từ YARA của các nhánh static và telemetry trong cùng lượt chạy.
        file_type / packer_detected: metadata report; ``file_type=None`` ⇒ suy từ
            ``cape_report.target.file.type``.

    Returns:
        :class:`PipelineResult`.
    """
    limitations: list[str] = []
    if not isinstance(artifact_sha256, str) or not SHA256_PATTERN.match(artifact_sha256):
        raise ValueError(
            f"artifact_sha256 phải là 64 ký tự hex, nhận {artifact_sha256!r}"
        )
    if prompt_guard_budget < 0:
        raise ValueError("prompt_guard_budget phải >= 0")
    if malware_analyzer is not None and agent_stub is not None:
        raise ValueError("malware_analyzer and agent_stub are mutually exclusive")

    malware_facts: FactsOutcome | None = None
    malware_source_binding_failed = False
    if malware_analyzer is not None:
        try:
            malware_facts = extract_malware_facts(
                cape_report,
                capa_report=capa_report,
                artifact_sha256=artifact_sha256,
                artifact_bytes=artifact_bytes,
                workflow=malware_analyzer.workflow,
            )
        except ValueError:
            malware_source_binding_failed = True


    # --- 1. Telemetry ingestion (Module 1, dynamic branch) ------------------
    ingestion = TelemetryIngestionAdapter().ingest(cape_report)
    if ingestion.errors:
        limitations.append(
            f"Telemetry ingestion ghi {len(ingestion.errors)} lỗi cấu trúc; coverage "
            f"{ingestion.coverage}."
        )

    # --- 2. Normalization (Module 0) ---------------------------------------
    engine = NormalizationEngine(load_confusables_map())
    telemetry_normalized = [
        engine.normalize(item["raw_string"], item["provenance"]) for item in ingestion.strings
    ]
    prompt_guard_inputs: list[tuple[NormalizedText, DetectionSource]] = [
        (item, DetectionSource.SANDBOX_API_LOG) for item in telemetry_normalized
    ]

    scanner = scanner if scanner is not None else YaraScanner()

    # --- 3. Detection branches ---------------------------------------------
    detector_results: list[DetectorResult] = []
    coverage: list[ProcessingState] = [ingestion.coverage]
    findings: list[EvidenceFinding] = []

    # 3a. Dynamic telemetry branch: YARA trên chuỗi đã chuẩn hoá.
    telemetry_scan = scanner.scan_normalized(
        telemetry_normalized, detection_source=DetectionSource.SANDBOX_API_LOG
    )
    coverage.append(telemetry_scan.coverage)
    yara_findings_for_context = list(telemetry_scan.findings)
    telemetry_findings = _dedupe_yara_findings(telemetry_scan.findings)
    telemetry_positive = bool(telemetry_findings)
    telemetry_errored = (
        ingestion.coverage is ProcessingState.FAILED
        or telemetry_scan.coverage is ProcessingState.FAILED
    )
    telemetry_has_provenance = all(
        finding.provenance is not None for finding in telemetry_findings
    )
    detector_results.append(
        _detector_result(
            DetectorName.TELEMETRY_ADAPTER,
            positive=telemetry_positive,
            score=1.0 if telemetry_positive else 0.0,
            errored=telemetry_errored,
            has_provenance=telemetry_has_provenance,
        )
    )
    for finding in telemetry_findings:
        findings.append(
            _yara_finding_to_evidence(
                finding,
                detector_name=DetectorName.TELEMETRY_ADAPTER,
                interpretation_summary=(
                    f"Rule YARA '{finding.rule}' khớp chuỗi telemetry đã chuẩn hoá "
                    f"(provenance {finding.provenance.get('locator') if finding.provenance else 'n/a'})."
                ),
            )
        )

    # 3b. Static artifact branch (tuỳ chọn).
    if artifact_bytes is not None:
        extraction = extract_strings(artifact_bytes)
        coverage.append(extraction.coverage)
        static_normalized = [
            engine.normalize(item["raw_string"], item["provenance"]) for item in extraction.strings
        ]
        prompt_guard_inputs.extend(
            (item, DetectionSource.STATIC_STRING) for item in static_normalized
        )
        static_scan = scanner.scan_normalized(static_normalized)
        yara_findings_for_context.extend(static_scan.findings)
        coverage.append(static_scan.coverage)
        static_findings = _dedupe_yara_findings(static_scan.findings)
        static_positive = bool(static_findings)
        detector_results.append(
            _detector_result(
                DetectorName.YARA_STATIC,
                positive=static_positive,
                score=1.0 if static_positive else 0.0,
                errored=extraction.coverage is ProcessingState.FAILED
                or static_scan.coverage is ProcessingState.FAILED,
                has_provenance=all(
                    finding.provenance is not None for finding in static_findings
                ),
            )
        )
        for finding in static_findings:
            findings.append(
                _yara_finding_to_evidence(
                    finding,
                    detector_name=DetectorName.YARA_STATIC,
                    interpretation_summary=(
                        f"Rule YARA '{finding.rule}' khớp strings trích từ artifact."
                    ),
                )
            )

    # 3c. Cuckoo module branch (tuỳ chọn).
    if cape_report_path is not None:
        cuckoo_scan = scanner.scan_cape_report(cape_report_path)
        coverage.append(cuckoo_scan.coverage)
        if cuckoo_scan.capability.flag:
            limitations.append(
                f"Cuckoo module không khả dụng ({cuckoo_scan.capability.flag}): "
                f"{cuckoo_scan.capability.reason}."
            )
        cuckoo_findings = _dedupe_yara_findings(cuckoo_scan.findings)
        detector_results.append(
            _detector_result(
                DetectorName.YARA_CUCKOO,
                positive=bool(cuckoo_findings),
                score=1.0 if cuckoo_findings else 0.0,
                errored=not cuckoo_scan.capability.available,
                has_provenance=True,
            )
        )
        for finding in cuckoo_findings:
            findings.append(
                _yara_finding_to_evidence(
                    finding,
                    detector_name=DetectorName.YARA_CUCKOO,
                    interpretation_summary=(
                        f"Rule Cuckoo '{finding.rule}' khớp report CAPEv2."
                    ),
                )
            )

    # 3d. Prompt Guard (Module 2) — luôn bắt buộc theo profile.
    if backend is None:
        # Không có backend ⇒ detector bắt buộc không chạy được. Không khởi tạo
        # TransformersPromptGuardBackend vì model gated, mọi nỗ lực nạp sẽ đi mạng.
        detector_results.append(
            _detector_result(
                DetectorName.META_PROMPT_GUARD,
                positive=False,
                errored=True,
                has_provenance=False,
            )
        )
        limitations.append(
            "Prompt Guard không có backend (model gated) — detector bắt buộc errored."
        )
    else:
        # InstructionOverrideContext (§3.4): kết luận của nhánh YARA — các chuỗi
        # ruleset tĩnh (họ override/verdict/role) đã khớp trong lượt chạy này.
        unique_texts = list(
            dict.fromkeys(item.normalized_string for item, _ in prompt_guard_inputs)
        )
        prompt_guard_overflow = len(unique_texts) > prompt_guard_budget
        selected_texts = set(unique_texts[:prompt_guard_budget])
        selected_prompt_guard_inputs = [
            (item, source)
            for item, source in prompt_guard_inputs
            if item.normalized_string in selected_texts
        ]
        yara_flagged_texts = frozenset(
            item.normalized_string
            for item, _ in selected_prompt_guard_inputs
            if any(
                finding.provenance == item.provenance
                for finding in yara_findings_for_context
            )
        )
        service = PromptGuardService(config=prompt_guard_config, backend=backend)
        try:
            (
                guard_findings,
                guard_errored,
                guard_coverage,
                guard_filtered,
            ) = _prompt_guard_findings(
                service,
                selected_prompt_guard_inputs,
                yara_flagged_texts=yara_flagged_texts,
                target_entity_is_llm=prompt_guard_target_entity_is_llm,
            )
        except PromptGuardError as exc:  # detector lỗi ⇒ INCONCLUSIVE, không âm tính giả
            detector_results.append(
                _detector_result(
                    DetectorName.META_PROMPT_GUARD,
                    positive=False,
                    errored=True,
                    has_provenance=False,
                )
            )
            limitations.append(f"Prompt Guard thất bại: {exc}")
        else:
            if prompt_guard_overflow:
                limitations.append(
                    "Prompt Guard vượt budget chung: "
                    f"bỏ qua {len(unique_texts) - prompt_guard_budget} chuỗi chuẩn hoá duy nhất; "
                    "coverage PARTIAL."
                )
                guard_coverage = _coverage_states(
                    (guard_coverage, ProcessingState.PARTIAL)
                )
            if guard_filtered:
                limitations.append(
                    f"Prompt Guard phát hiện {guard_filtered} chuỗi đối kháng nhưng thiếu "
                    "ngữ cảnh promptware §3.4 (TargetEntityIsLLM=False và không có kết "
                    "luận YARA) — không nâng thành finding."
                )
            detector_results.append(
                _detector_result(
                    DetectorName.META_PROMPT_GUARD,
                    positive=bool(guard_findings),
                    score=max(
                        (float(item.get("score", 0.0)) for item in guard_findings),
                        default=0.0,
                    ),
                    errored=guard_errored,
                    has_provenance=not guard_errored,
                )
            )
            findings.extend(guard_findings)
            coverage.append(guard_coverage)
        finally:
            service.close()

    # --- 4. Policy gate ----------------------------------------------------
    required_detectors = tuple(str(result["name"]) for result in detector_results)
    processing_state = _coverage_states(coverage) if coverage else ProcessingState.FAILED
    evaluation = evaluate_policy(detector_results, required_detectors, processing_state)
    detection_state = evaluation.detection_state
    outcome = evaluation.outcome

    # --- 5. Evidence emission ---------------------------------------------
    telemetry_provenance: Mapping[str, object] = (
        telemetry_normalized[0].provenance if telemetry_normalized else {"locator": "/behavior"}
    )
    detection_seed = _coverage_seed(
        detector_results,
        telemetry_provenance,
        (
            "Coverage gap/bản ghi quarantine: policy gate §3.5.1 quyết định "
            f"{outcome.pipeline_action} cho cặp {processing_state}/{detection_state}."
        ),
    )
    evidence = emit_policy_evidence(
        outcome,
        artifact_sha256=artifact_sha256,
        year=year,
        first_sequence=first_evidence_sequence,
        findings=findings,
        detection=detection_seed,
        raw_telemetry=build_provenance(
            ProvenanceType.JSON_LOG_POINTER, locator=str(telemetry_provenance.get("locator", "/behavior"))
        ),
    )
    sequence = first_evidence_sequence + len(evidence)

    # --- 6. Capabilities (Module 3) ---------------------------------------
    capabilities: list[dict[str, str]] = []
    if capa_report is not None:
        try:
            capabilities = [dict(row) for row in project_capabilities(capa_report)]
        except CapaProjectionError as exc:
            limitations.append(f"CAPA projection thất bại: {exc}")

    resolved_file_type = file_type if file_type is not None else _derive_file_type(cape_report)

    # --- 7. Output governance: report hoặc abstention trực tiếp -----------
    if not outcome.forward_to_agent:
        report = build_fallback_report(
            artifact_sha256=artifact_sha256,
            file_type=resolved_file_type,
            packer_detected=packer_detected,
            reason=(
                f"Pipeline processing {processing_state}: không chuyển context cho agent "
                "và không hỏi verdict (§3.5.1 hàng FAILED)."
            ),
            validation_errors=[],
            capabilities=capabilities,
            status_flags=outcome.status_flags,
        )
        check = validate_final_report(report, evidence_store=evidence)
        if not check.valid:
            raise PipelineError(f"fallback report không hợp lệ: {check.errors}")
        malware_analysis = (
            _laya_companion(
                malware_analyzer,
                malware_facts,
                source_binding_failed=malware_source_binding_failed,
                artifact_sha256=artifact_sha256,
                processing_state=processing_state,
                detection_state=detection_state,
                outcome=outcome,
            )
            if malware_analyzer is not None
            else None
        )
        return PipelineResult(
            artifact_sha256=artifact_sha256,
            processing_state=processing_state,
            detection_state=detection_state,
            decision=outcome,
            detector_results=detector_results,
            required_detectors=required_detectors,
            capabilities=capabilities,
            evidence=evidence,
            payload=None,
            agent_invoked=False,
            report=report,
            report_outcome=ReportOutcome(
                report=report,
                attempts=0,
                errors=[],
                abstained=True,
            ),
            canary=None,
            limitations=limitations,
            malware_analysis=malware_analysis,
        )

    # --- 8. Spotlighting context ------------------------------------------
    summaries = [summarize_finding(record) for record in evidence]
    spotted = build_chat_payload(
        model=model,
        static_capabilities=capabilities,
        findings=summaries,
        canaries=canaries,
        sha256=artifact_sha256,
    )

    # --- 9. Execution rails + agent step ----------------------------------
    dispatcher: ReadOnlyDispatcher | None = None
    if dispatcher_store is not None:
        dispatcher = ReadOnlyDispatcher(
            dispatcher_store,
            artifact_sha256=artifact_sha256,
            year=year,
            first_evidence_sequence=sequence,
        )

    agent: Callable[[AgentRequest], object]
    if agent_stub is not None:
        agent = agent_stub
    else:
        agent = SimulatedAgent(
            artifact_sha256=artifact_sha256,
            file_type=resolved_file_type,
            packer_detected=packer_detected,
            capabilities=capabilities,
            evidence=evidence,
            outcome=outcome,
            status_flags=outcome.status_flags,
        )

    validator = ReportValidator(
        evidence_store=evidence, banned_verdicts=outcome.banned_verdicts
    )
    controller = ReAskController(validator, max_re_asks=max_re_asks)

    def fallback_factory(errors: list[str]) -> Mapping[str, object]:
        return build_fallback_report(
            artifact_sha256=artifact_sha256,
            file_type=resolved_file_type,
            packer_detected=packer_detected,
            reason=(
                f"Report không hợp lệ sau {controller.max_attempts} lượt sinh: "
                "abstention thay vì ép verdict (§3.6)."
            ),
            validation_errors=errors,
            capabilities=capabilities,
            status_flags=outcome.status_flags,
        )

    report_outcome = controller.run(
        agent, payload=spotted.payload, tools=dispatcher, fallback_factory=fallback_factory
    )
    report = report_outcome.report

    # Dispatcher chặn tool-call trong lượt agent: bảo toàn vào kho evidence.
    if dispatcher is not None and dispatcher.blocked_evidence:
        evidence = list(evidence) + dispatcher.blocked_evidence
        limitations.append(
            f"Dispatcher chặn {len(dispatcher.blocked_evidence)} tool-call trái phép "
            "(HARD_BLOCK, không side effect)."
        )

    malware_analysis = (
        _laya_companion(
            malware_analyzer,
            malware_facts,
            source_binding_failed=malware_source_binding_failed,
            artifact_sha256=artifact_sha256,
            processing_state=processing_state,
            detection_state=detection_state,
            outcome=outcome,
        )
        if malware_analyzer is not None
        else None
    )
    # --- 10. Canary Token Verifier ----------------------------------------
    canary_verdict: CanaryVerdict | None = None
    if canaries:
        verifier = CanaryVerifier(
            canaries,
            artifact_sha256=artifact_sha256,
            year=year,
            first_evidence_sequence=sequence + (
                len(dispatcher.blocked_evidence) if dispatcher is not None else 0
            ),
        )
        canary_input: object = report
        if malware_analysis is not None:
            canary_input = {
                "report": report,
                "malware_analysis": dict(malware_analysis),
            }
        canary_verdict = verifier.verify(canary_input)
        if canary_verdict.leaked:
            evidence = list(evidence) + list(canary_verdict.evidence)
            sanitized_report: object = canary_verdict.output
            if malware_analysis is not None:
                if not isinstance(canary_verdict.output, Mapping) or "report" not in canary_verdict.output:
                    raise PipelineError("canary verifier returned an invalid companion envelope")
                sanitized_report = canary_verdict.output["report"]
                if any(
                    hit.locator.startswith("report.malware_analysis")
                    for hit in canary_verdict.hits
                ):
                    assert malware_analyzer is not None
                    malware_analysis = malware_analyzer.blocked(
                        None,
                        artifact_sha256=artifact_sha256,
                        reason="OUTPUT_CANARY_LEAK",
                        limitations=[
                            "Canary detected in malware_analysis; facts and links were withheld."
                        ],
                    )
                    _validate_laya_companion(
                        malware_analysis,
                        _empty_malware_facts(),
                        malware_analyzer,
                        artifact_sha256,
                    )
            patched = _merge_canary_findings(sanitized_report, canary_verdict)
            check = validate_final_report(
                patched,
                evidence_store=evidence,
                banned_verdicts=outcome.banned_verdicts,
            )
            if check.valid:
                report = patched
                report_outcome = report_outcome._replace(report=patched)
            else:
                report = build_fallback_report(
                    artifact_sha256=artifact_sha256,
                    file_type=resolved_file_type,
                    packer_detected=packer_detected,
                    reason="Output agent rò rỉ canary và không sửa được thành report hợp lệ.",
                    validation_errors=check.errors,
                    capabilities=capabilities,
                    status_flags=outcome.status_flags,
                )
                report_outcome = ReportOutcome(
                    report=report,
                    attempts=report_outcome.attempts,
                    errors=check.errors,
                    abstained=True,
                )
            if malware_analysis is not None:
                canary_verdict = canary_verdict._replace(
                    output={
                        "report": dict(report),
                        "malware_analysis": dict(malware_analysis),
                    }
                )
            limitations.append(
                "Output agent hoặc companion malware_analysis rò rỉ canary/marker hệ thống: "
                "đã tước nội dung và không phát hành output gốc."
            )
    if not isinstance(report, Mapping):
        raise PipelineError("final report is not a mapping")

    return PipelineResult(
        artifact_sha256=artifact_sha256,
        processing_state=processing_state,
        detection_state=detection_state,
        decision=outcome,
        detector_results=detector_results,
        required_detectors=required_detectors,
        capabilities=capabilities,
        evidence=evidence,
        payload=spotted,
        agent_invoked=True,
        report=report,
        report_outcome=report_outcome,
        canary=canary_verdict,
        limitations=limitations,
        malware_analysis=malware_analysis,
    )


def _merge_canary_findings(
    output: object, verdict: CanaryVerdict
) -> Mapping[str, object]:
    """Ghép bản ghi canary vào report đã tước nội dung (Finding Preservation Rule)."""
    if not isinstance(output, Mapping):
        raise PipelineError("output đã tước canary phải là report object")
    report: dict[str, object] = dict(output)
    findings = report.get("adversarial_evasion_findings")
    if not isinstance(findings, Mapping):
        findings = {"prompt_injection_detected": True, "evasion_attempts": []}
    attacks = list(findings.get("evasion_attempts") or [])
    known = {
        item.get("evidence_id")
        for item in attacks
        if isinstance(item, Mapping)
    }
    for record in verdict.evidence:
        summary = summarize_finding(record)
        if summary["evidence_id"] in known:
            continue
        attacks.append(summary)
    report["adversarial_evasion_findings"] = {
        "prompt_injection_detected": True,
        "evasion_attempts": attacks,
    }
    return report
