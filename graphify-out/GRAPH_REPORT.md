# Graph Report - PTMD  (2026-09-19)

## Corpus Check
- Corpus is ~12,761 words - fits in a single context window. You may not need a graph.

## Summary
- 119 nodes · 213 edges · 10 communities (9 shown, 1 thin omitted)
- Extraction: 79% EXTRACTED · 20% INFERRED · 1% AMBIGUOUS · INFERRED: 42 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Domain Ontology & Core Concepts
- CAPA vs CAPEv2 Separation
- AI-SOC & Defense Architectures
- Threat Model & ATLAS 2026.09
- Decoupled Detection & ML Guard
- Passive Agent & Execution Rails
- Tag-as-Evidence & Quarantine
- Decision Policy & Evidence Schema
- Evaluation & Red Teaming
- External Threat Case Studies

## God Nodes (most connected - your core abstractions)
1. `Nghiên cứu kiến trúc Guardrail đa tầng chống Indirect Prompt Injection` - 17 edges
2. `Security Standards Mapping Matrix (ATLAS 2026.09 / OWASP 2025)` - 14 edges
3. `CAPEv2 Sandbox` - 13 edges
4. `End-to-End Static & Dynamic Guardrail Pipeline` - 12 edges
5. `Mandiant CAPA` - 10 edges
6. `Lớp 3 — Meta Prompt Guard-86M` - 10 edges
7. `Promptware` - 9 edges
8. `Quyết định ưu tiên Tag-as-Evidence khi phát hiện Promptware` - 9 edges
9. `SPEC-SEC-AI-2026-01 — Đặc tả Guardrail đa tầng v1.1.0` - 9 edges
10. `Quyết định: Agent là Passive Consumer, không điều khiển Sandbox` - 8 edges

## Surprising Connections (you probably didn't know these)
- `Nguyên tắc: Không phát hiện không đồng nghĩa an toàn` --conceptually_related_to--> `Indirect Prompt Injection (IPI)`  [AMBIGUOUS]
  issues/issue_2026-09-18_review_intent_specs.md → CONTEXT.md
- `Quarantined Evidence Schema v1.1` --semantically_similar_to--> `Quarantined Evidence`  [INFERRED] [semantically similar]
  specs/guardrail_malware_agent_spec.md → CONTEXT.md
- `Neurosymbolic Defense-in-Depth Pipeline` --semantically_similar_to--> `Malware Analysis Agent Guardrail`  [INFERRED] [semantically similar]
  specs/guardrail_malware_agent_spec.md → CONTEXT.md
- `MCP (Model Context Protocol) — phương án bị loại` --conceptually_related_to--> `CAPEv2 Sandbox`  [INFERRED]
  docs/adr/0003-passive-consumer-agent.md → CONTEXT.md
- `Lớp 5 — Runtime Execution Rails & Output Governance` --semantically_similar_to--> `Execution Rails`  [INFERRED] [semantically similar]
  specs/guardrail_malware_agent_spec.md → CONTEXT.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Static & Dynamic Guardrail Toolchain** — links_capev2_sandbox, links_pe_sieve, links_mandiant_capa, links_yara_cuckoo_module, links_meta_prompt_guard, links_nemo_guardrails, links_guardrails_ai [EXTRACTED 1.00]
- **Guardrail Ontology (CONTEXT.md glossary)** — context_guardrail_system, context_malware_sample, context_promptware, context_indirect_prompt_injection, context_capev2_sandbox, context_mandiant_capa, context_yara, context_meta_prompt_guard, context_tag_as_evidence, context_passive_consumer_agent, context_quarantined_evidence, context_execution_rails [EXTRACTED 1.00]
- **Guardrail đa tầng — Lớp 0→5 (Neurosymbolic Defense-in-Depth)** — specs_guardrail_malware_agent_spec_neurosymbolic_defense_in_depth, specs_guardrail_malware_agent_spec_normalization_engine, specs_guardrail_malware_agent_spec_yara_engine, specs_guardrail_malware_agent_spec_capa_abstraction_layer, specs_guardrail_malware_agent_spec_prompt_guard_86m, specs_guardrail_malware_agent_spec_decision_policy_matrix, specs_guardrail_malware_agent_spec_runtime_execution_rails [EXTRACTED 1.00]
- **Hai nhánh dữ liệu song song: Detection Branch & Capability Branch** — intent_research_pre_validate_detection_branch, intent_research_pre_validate_capability_branch, specs_guardrail_malware_agent_spec_normalization_engine, specs_guardrail_malware_agent_spec_yara_engine, specs_guardrail_malware_agent_spec_prompt_guard_86m, specs_guardrail_malware_agent_spec_capa_abstraction_layer [EXTRACTED 1.00]
- **OWASP LLM Top 10 (2025) — các mục được ánh xạ** — specs_guardrail_malware_agent_spec_owasp_llm_top10_2025, specs_guardrail_malware_agent_spec_owasp_llm01_2025, specs_guardrail_malware_agent_spec_owasp_llm06_2025, specs_guardrail_malware_agent_spec_owasp_llm07_2025 [EXTRACTED 1.00]
- **Tập kỹ thuật MITRE ATLAS được ánh xạ trong bảng chuẩn** — specs_guardrail_malware_agent_spec_aml_t0051_001, specs_guardrail_malware_agent_spec_aml_t0015, specs_guardrail_malware_agent_spec_aml_t0043, specs_guardrail_malware_agent_spec_aml_t0053, specs_guardrail_malware_agent_spec_aml_t0054, specs_guardrail_malware_agent_spec_aml_t0056 [EXTRACTED 1.00]
- **Bộ 3 ADR chuẩn hóa quyết định kiến trúc then chốt** — context_guardrail_system, docs_adr_0001_separate_capa_from_capev2_decision, docs_adr_0002_tag_as_evidence_over_hard_block_decision, docs_adr_0003_passive_consumer_agent_decision [EXTRACTED 1.00]
- **Tám phát hiện review F01–F08 (2026-09-18)** — issues_issue_2026_09_18_review_intent_specs_f01, issues_issue_2026_09_18_review_intent_specs_f02, issues_issue_2026_09_18_review_intent_specs_f03, issues_issue_2026_09_18_review_intent_specs_f04, issues_issue_2026_09_18_review_intent_specs_f05, issues_issue_2026_09_18_review_intent_specs_f06, issues_issue_2026_09_18_review_intent_specs_f07, issues_issue_2026_09_18_review_intent_specs_f08 [EXTRACTED 1.00]

## Communities (10 total, 1 thin omitted)

### Community 0 - "Domain Ontology & Core Concepts"
Cohesion: 0.12
Nodes (24): CONTEXT.md — Guardrail Ontology Glossary, Malware Analysis Agent Guardrail, Indirect Prompt Injection (IPI), Malware Sample, AI-SOC Neurosymbolic (arXiv:2609.10707, 2026), Giả thuyết nghiên cứu trọng tâm, Nghiên cứu kiến trúc Guardrail đa tầng chống Indirect Prompt Injection, Greshake et al. — Indirect Prompt Injection (paper gốc) (+16 more)

### Community 1 - "CAPA vs CAPEv2 Separation"
Cohesion: 0.17
Nodes (20): CAPEv2 Sandbox, Mandiant CAPA, MITRE ATT&CK, YARA, Thuật ngữ nhập nhằng 'CAPA Sandbox', Data Sanitizer (vai trò của Mandiant CAPA), Quyết định tách biệt CAPEv2 Sandbox và Mandiant CAPA, ADR 0001 — Phân định Mandiant CAPA và CAPEv2 Sandbox (+12 more)

### Community 2 - "AI-SOC & Defense Architectures"
Cohesion: 0.16
Nodes (17): Secure AI-SOC Neurosymbolic Framework (arXiv:2609.10707), CAPEv2 Sandbox, End-to-End Static & Dynamic Guardrail Pipeline, Google Cloud SAIF & Model Armor, Greshake et al. - Indirect Prompt Injection, Guardrails AI, Bypassing LLM Guardrails (Hackett et al., 2025), Mandiant CAPA (+9 more)

### Community 3 - "Threat Model & ATLAS 2026.09"
Cohesion: 0.22
Nodes (14): Excessive Agency risk, Threat Model (Attacker, Attack Surface, Vector), F05 — Mapping MITRE có lỗi định danh và suy diễn quá mức, AML.T0043 — Craft Adversarial Data, AML.T0051.001 — Indirect Prompt Injection, AML.T0053 — AI Agent Tool Invocation, AML.T0056 — System Prompt Extraction, ATT&CK T1059.003 — Windows Command Shell (+6 more)

### Community 4 - "Decoupled Detection & ML Guard"
Cohesion: 0.25
Nodes (11): DeBERTa-v2, Meta Prompt Guard, Detection Branch (Nhánh Phát hiện), F02 — Sơ đồ pipeline và mô tả thành phần không khớp, AML.T0015 — Evade ML Model, AML.T0054 — LLM Jailbreak, ATT&CK T1027 — Obfuscated Files or Information, Lớp 0 — Normalization & De-obfuscation Engine (+3 more)

### Community 5 - "Passive Agent & Execution Rails"
Cohesion: 0.25
Nodes (11): Execution Rails, Passive Consumer Agent, Quyết định: Agent là Passive Consumer, không điều khiển Sandbox, ADR 0003 — Định vị Agent theo mô hình Passive Consumer, Interactive Controller (phương án bị loại), MCP (Model Context Protocol) — phương án bị loại, Final Output Report Schema v1.1, Guardrails AI (+3 more)

### Community 6 - "Tag-as-Evidence & Quarantine"
Cohesion: 0.33
Nodes (9): Promptware, Quarantined Evidence, Tag-as-Evidence, Quyết định ưu tiên Tag-as-Evidence khi phát hiện Promptware, ADR 0002 — Tag-as-Evidence thay vì Hard Block, Hard Block policy, Threat Intelligence preservation, False Positive Dilemma (+1 more)

### Community 7 - "Decision Policy & Evidence Schema"
Cohesion: 0.25
Nodes (8): F01 — XML/Spotlighting bị coi là ranh giới bảo mật tuyệt đối, F03 — Chưa định nghĩa quyết định khi quét thất bại/không đầy đủ, F07 — Evidence schema chưa đáp ứng truy vết và mapping, Microsoft — How Microsoft defends against indirect prompt injection attacks, Nguyên tắc: Không phát hiện không đồng nghĩa an toàn, Lớp 4 — Decision Policy Gate (ma trận 3 chiều), Microsoft Spotlighting & Prompt Isolation, Quarantined Evidence Schema v1.1

### Community 8 - "Evaluation & Red Teaming"
Cohesion: 0.50
Nodes (4): Garak, MITRE ATLAS, OWASP Top 10 for LLM Applications (2025), Microsoft PyRIT

## Ambiguous Edges - Review These
- `Indirect Prompt Injection (IPI)` → `Nguyên tắc: Không phát hiện không đồng nghĩa an toàn`  [AMBIGUOUS]
  issues/issue_2026-09-18_review_intent_specs.md · relation: conceptually_related_to
- `PE-sieve (RAM scan & unpacked PE dump)` → `ATT&CK T1497 — Virtualization/Sandbox Evasion`  [AMBIGUOUS]
  specs/guardrail_malware_agent_spec.md · relation: conceptually_related_to

## Knowledge Gaps
- **30 isolated node(s):** `Vigil-LLM`, `Meta Prompt Guard-86M`, `Protect AI LLM Guard`, `Guardrails AI`, `Garak` (+25 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 30 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Indirect Prompt Injection (IPI)` and `Nguyên tắc: Không phát hiện không đồng nghĩa an toàn`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `PE-sieve (RAM scan & unpacked PE dump)` and `ATT&CK T1497 — Virtualization/Sandbox Evasion`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `Nghiên cứu kiến trúc Guardrail đa tầng chống Indirect Prompt Injection` connect `Domain Ontology & Core Concepts` to `CAPA vs CAPEv2 Separation`, `Decoupled Detection & ML Guard`, `Decision Policy & Evidence Schema`?**
  _High betweenness centrality (0.160) - this node is a cross-community bridge._
- **Why does `Review intent và spec: Guardrail chống IPI cho agent phân tích mã độc (2026-09-18)` connect `Domain Ontology & Core Concepts` to `CAPA vs CAPEv2 Separation`, `Passive Agent & Execution Rails`, `Tag-as-Evidence & Quarantine`?**
  _High betweenness centrality (0.096) - this node is a cross-community bridge._
- **Why does `CAPEv2 Sandbox` connect `CAPA vs CAPEv2 Separation` to `Threat Model & ATLAS 2026.09`, `Decoupled Detection & ML Guard`, `Passive Agent & Execution Rails`?**
  _High betweenness centrality (0.094) - this node is a cross-community bridge._
- **Are the 3 inferred relationships involving `CAPEv2 Sandbox` (e.g. with `Mandiant CAPA` and `Thuật ngữ nhập nhằng 'CAPA Sandbox'`) actually correct?**
  _`CAPEv2 Sandbox` has 3 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `End-to-End Static & Dynamic Guardrail Pipeline` (e.g. with `Secure AI-SOC Neurosymbolic Framework (arXiv:2609.10707)` and `Greshake et al. - Indirect Prompt Injection`) actually correct?**
  _`End-to-End Static & Dynamic Guardrail Pipeline` has 4 INFERRED edges - model-reasoned connections that need verification._