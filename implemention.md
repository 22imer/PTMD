# Implementation Plan — Guardrail cho Malware Analysis Agent

**Status (2026-09-21):** T00 gate PASS; T01–T08 PASS theo verdict supervisor (prototype correctness); smoke E2E chạy với stub backend; T09–T10 có protocol + harness nhưng **phép đo thực nghiệm bị chặn**; chưa chứng minh bất kỳ target SLA nào. Bằng chứng chuẩn: `reports/phase0-gate.json` và `reports/build-report.md` (§3 verdict, §5 blocked); khoảng cách còn mở và thứ tự khép: `audit.md` A01–A06 → `PLAN.md` §7.  
**Goal:** Cụ thể hóa `PLAN.md` thành các task có chủ sở hữu, đầu vào/đầu ra, phụ thuộc và bằng chứng nghiệm thu.  
**Architecture:** Detection Branch chuẩn hóa dữ liệu trích xuất trước YARA/Meta Prompt Guard; Capability Branch dùng Mandiant CAPA độc lập. Hai nhánh hội tụ ở Decision Policy Gate, sau đó Context Serialization và Execution Rails bảo vệ Passive Consumer Agent.  
**Tech Stack theo spec:** Python, YARA, CAPEv2 report, Mandiant CAPA, Meta Prompt Guard-86M, JSON Schema Draft-07 + `jsonschema` (ADR-0004 hoãn Guardrails AI). Không bổ sung web framework, cơ sở dữ liệu hay nền tảng triển khai mới.  
**Spec:** [SPEC-SEC-AI-2026-01 v1.4.0](specs/guardrail_malware_agent_spec.md), trạng thái Draft — Pending Empirical Validation.

> Đọc [AGENTS.md](AGENTS.md) trước khi thao tác. Tick ở đây chỉ nghĩa "bằng chứng ghi kèm đã có"; verdict wave và checkbox **không** thay nghiệm thu tích hợp hay hiệu quả thực nghiệm.

## 1. Nguồn, phạm vi và ràng buộc

| Nguồn hiện có | Vai trò khi thực thi |
|---|---|
| [PLAN.md](PLAN.md) | Phase 0 → Phase 2 Module 0–4 → Phase 3; §7 là backlog ưu tiên sau audit. |
| [AGENTS.md](AGENTS.md) | Ràng buộc thao tác và quy ước tài liệu. |
| [audit.md](audit.md) | Khoảng cách A01–A06 giữa intent → spec → code → bằng chứng. |
| [Spec v1.4.0](specs/guardrail_malware_agent_spec.md) | Contract kỹ thuật; mục/dòng trích bên dưới là của v1.4.0 (thay line range cũ trong PLAN). |
| [Research intent v1.2.1](intent/research_pre_validate.md) | Mục tiêu nghiên cứu, giới hạn phạm vi; §7 là nghiệm thu nghiên cứu, không phải bằng chứng prototype chạy được. |
| [CONTEXT.md](CONTEXT.md) | Single source of truth cho thuật ngữ và danh sách `_Avoid_`. |
| [ADR-0001](docs/adr/0001-separate-capa-from-capev2.md), [ADR-0002](docs/adr/0002-tag-as-evidence-over-hard-block.md), [ADR-0003](docs/adr/0003-passive-consumer-agent.md), [ADR-0004](docs/adr/0004-jsonschema-as-report-validator.md), [ADR-0005](docs/adr/0005-pyright-advisory-gate-with-ratchet.md) | Phân tách CAPA/CAPEv2, Tag-as-Evidence, Passive Consumer Agent, `jsonschema` thay Guardrails AI, pyright ratchet. |
| [Issue review 2026-09-18](issues/issue_2026-09-18_review_intent_specs.md), [issue R01–R08](issues/issue_2026-09-19_unresolved_spec_review.md), [issue 2026-09-20](issues/issue_2026-09-20_full_project_review_new_findings.md) | Lịch sử review và điều kiện mở gate. |
| [links.md](links.md) | Nguồn primary cần đối chiếu khi kiểm chứng tích hợp và mapping. |
| [CAPE fixture vô hại](tests/fixtures/cape_report_sample_harmless.json) | Dữ liệu đầu vào có sẵn; không tự chứng minh YARA/CAPE tương thích. |

### Global Constraints

- Không thực thi, unpack hoặc chạy Malware Sample/binary trong repo. Dữ liệu động chỉ nhận từ artifact đã thu thập trong lab được phê duyệt, không trao quyền điều khiển lab cho Agent.
- Windows PE 32/64-bit (`.exe`, `.dll`, `.sys`); giữ PE gốc bất biến (spec §1.2, dòng 25–27).
- Strings, telemetry, log và tool-returned data luôn là untrusted data. Chỉ metadata/summary được duyệt vào context; evidence nguyên bản lưu riêng.
- Agent chỉ được dùng ba hàm truy vấn read-only trong spec §3.6; không shell, ghi file hoặc network tool. Quy tắc này áp dụng quyền của Agent, không phải quyền lưu artifact của pipeline tin cậy.
- Mọi tuyên bố hiệu quả là mục tiêu cần kiểm chứng; schema hợp lệ không chứng minh kết luận đúng hoặc rủi ro ngữ nghĩa đã bị loại bỏ.
- Giữ MITRE ATLAS Snapshot 2026.09, OWASP LLM Top 10 (2025), NIST AI RMF và CSA MAESTRO như chuẩn tham chiếu. Mọi mã ATLAS cần đối chiếu [snapshot primary](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.09.yaml); không gán ATT&CK chỉ từ quyền tool hoặc câu lệnh quan sát được.
- Đường dẫn tệp trong §4–§5 là tệp thật trong repo; module map và test seam ở [`src/guardrail/README.md`](src/guardrail/README.md). Không tạo microservice/network API chỉ vì spec dùng từ “service”.

## 2. Phase 0 — Gate trước triển khai

Gate **PASS ngày 2026-09-19** trên spec v1.4.0 sau fix D01–D18: 8/8 R-item CLOSED theo tái kiểm tra độc lập ⇒ Phase 2 được phép khởi động. Verdict từng R-item, lịch sử audit v1/v2, roster executor–supervisor và quyết định D01–D18 nằm trọn ở `reports/phase0-gate.json` — không lặp lại ở đây.

### T00 — Tái kiểm tra baseline và đóng các contract còn lệch

**Owner:** Integration owner cùng người review spec.  
**Nguồn:** `PLAN.md` §2; issue 2026-09-19 §4/§6; spec v1.4.0 (v1.3.0 là bản được audit v1).  
**Đầu vào → Đầu ra:** tài liệu và fixture hiện có → biên bản gate có phiên bản/hash, từng R-item, bằng chứng, người kiểm tra và kết luận pass/block.  
**Phụ thuộc:** không có; gate đã PASS nên T01–T10 được mở.  
**Tệp đã tác động:** issue R01–R08, `PLAN.md`, spec → v1.4.0, `docs/adr/0002`/`0003`, `links.md`, `intent/research_pre_validate.md` v1.2.1, fixture metadata, `reports/phase0-gate.json`, `reports/integration-pin.json`.

| ID | Việc cần xác nhận | Bằng chứng để đóng |
|---|---|---|
| R01 | 9 tổ hợp state; bảo toàn positive finding khi PARTIAL/FAILED; sanitization/escalation; tổng hợp detector và hết re-ask. | Ma trận input/output thống nhất với evidence/report; quy tắc detector disagreement và fallback được ghi rõ. |
| R02 | Ingress áp dụng cả dữ liệu tool trả về; tách evidence nguyên bản khỏi context; residual risk nhất quán. | Review spec, CONTEXT, cả ba ADR và links; không đồng nhất escaping với bảo đảm an toàn ngữ nghĩa. |
| R03 | Extraction trước normalization cho PE/memory/log; provenance và transform chain không mất. | Trace một artifact qua extraction → normalized text → finding → report, truy hồi được nguồn. |
| R04 | YARA/CAPE/report format/build options và cơ chế nạp report tương thích. | Phiên bản/build cụ thể, fixture metadata/hash và log tương thích; fixture tồn tại không đủ để tick. |
| R05 | Mapping theo taxonomy có phiên bản; phân biệt instruction, attempted invocation và executed action. | Đối chiếu primary snapshot, thống nhất spec/ADR/links; không tự thêm ATT&CK khi thiếu hành vi. |
| R06 | Paired samples, hai ground truth độc lập, split chống leakage, bốn baseline và attack success. | Dataset protocol nêu rõ bốn nhóm, nhãn và denominator; phân chia không trùng pair/family. |
| R07 | Transform provenance, multi/no-mapping, evidence reference và pipeline/evidence action. | Schema cùng ví dụ valid/invalid cho từng nhánh, đối chiếu ID report với evidence thật. |
| R08 | Workload/hardware/runtime/batch/concurrency/percentile và fallback output. | Measurement protocol có ranh giới đo, baseline, denominator; compliance và abstention tách riêng. |

- [x] Đối chiếu từng R-item với nội dung v1.3.0 và bằng chứng có thật, không chỉ header Closed.
- [x] Giải quyết các điểm lệch bằng sửa tài liệu/ADR đúng quy ước; không dựng adapter tương thích giả để che contract thiếu.
- [x] Kiểm chứng tích hợp bằng fixture vô hại; ghi rõ phạm vi chưa kiểm chứng.
- [x] Tick checklist issue chỉ khi có bằng chứng; đồng bộ status/intent/PLAN với kết quả.

**Nghiệm thu:** tất cả R01–R08 pass, checklist §6 issue được xác nhận; không còn contract bắt buộc mà người thực thi phải tự đoán. Bất kỳ mục nào chưa đạt → giữ gate block, vẫn có thể hoàn thiện tài liệu nhưng không bắt đầu build.

## 3. Contract chung và bố trí tệp

Integration owner sở hữu các contract này; các worker dùng cùng một bản đã chốt tại T01.

| Biên dữ liệu | Contract cần giữ |
|---|---|
| Extraction → Module 0 | Chuỗi bản sao + artifact identity + `provenance` với `type`, `locator`, `section_or_pid`; loại nguồn phân biệt file/memory/log. Metadata API/timestamp không làm thay đổi độ tin cậy của text. |
| Module 0 → Detector | `NormalizedText`: `normalized_string`, `provenance`, `decoding_depth`, `transform_chain` (spec dòng 134–143); liên kết tới representation gốc vẫn tồn tại. |
| Detector → Policy | Finding giữ artifact/provenance, detector name/version/score, transform chain; processing state độc lập detection state, không đổi lỗi detector thành NOT_DETECTED. |
| CAPA → Policy/Context | Capability projection chỉ `tactic`, `technique_id`, `technique_name`, `namespace`; không raw strings/disassembly/API log. Giá trị vẫn phải qua ingress. |
| Policy → Evidence | `pipeline_action` khác `policy_decision`; dùng mapping §3.5.1 đã được T00 kiểm tra, không ép hai enum bằng nhau. |
| Evidence → Report | `evidence_id` của mọi evasion attempt phải tồn tại trong kho evidence cùng artifact; mapping trong report truy nguyên được. |
| Context/Tool → Agent | Chỉ dữ liệu được duyệt, giữ cờ untrusted; system instructions tách khỏi dữ liệu. |

**Bố trí tệp:** module trong `src/guardrail/` (+ `src/guardrail/evaluation/` cho Phase 3), hai schema Draft-07 trong `schemas/`, luật trong `rules/`, test/fixture trong `tests/`, artifact kiểm chứng trong `reports/`. Xem module map chi tiết ở [`src/guardrail/README.md`](src/guardrail/README.md).

## 4. Phase 2 — Các task triển khai prototype

**Trạng thái (2026-09-21):** T01–T08 PASS theo verdict supervisor (`reports/build-report.md` §3), kèm các residual mở và waiver ở §5 của báo cáo đó; smoke E2E chạy với `SimulatedAgent` + stub backend, không phải agent/model thật.

### T01 — Chốt contract, schema và môi trường tái lập

**Owner:** Integration owner. **Phụ thuộc:** T00 pass.  
**Nguồn:** spec §3.1 (dòng 136–146), §3.5–3.6 (dòng 313–374), §4 (dòng 378–619).  
**Tệp:** `src/guardrail/contracts.py`, `schemas/quarantined_evidence.schema.json`, `schemas/final_report.schema.json`, `pyproject.toml`, `tests/test_contracts.py`, `reports/environment.json`.  
**Đầu vào → Đầu ra:** contract đã đóng gate → kiểu dữ liệu/schema dùng chung và manifest môi trường khóa phiên bản.

- [x] Tách hai JSON Schema Draft-07 từ spec đã sửa qua T00; hiện thực provenance, state và các record đúng vocabulary, không chép lỗi ví dụ cũ.
- [x] Chốt dependency/runtime và model/ruleset revision cụ thể trong `reports/integration-pin.json`; ghi build options Cuckoo, phần cứng và hash nguồn.
- [x] Kiểm chứng các bản ghi: nhiều mapping, no-mapping, coverage gap, positive finding, fallback. Kiểm tra bổ sung semantic reference/state ngoài JSON Schema.
- [x] Xuất manifest và thông báo contract đã ổn định trước khi giao việc song song; một owner sửa shared schema.

**Nghiệm thu:** validator nhận record hợp lệ, từ chối thiếu trường/enum sai; quan hệ state/action và report/evidence được kiểm riêng. Không đưa record có `SANDBOX_API_TRACE` vào schema hiện hành.

### T02 — Extraction và Telemetry Ingestion Adapter (phần đầu Module 1)

**Owner:** Detection worker. **Phụ thuộc:** T01.  
**Nguồn:** spec §2 (sơ đồ trích xuất, dòng 63–71), §3.2.1 (dòng 213–217), §3.2.2 (dòng 238–294).  
**Tệp:** `src/guardrail/extraction.py`, `src/guardrail/telemetry.py`, `tests/test_extraction.py`, `tests/test_telemetry.py`; tái sử dụng CAPE fixture hiện có.  
**Đầu vào → Đầu ra:** artifact PE/memory và CAPE JSON đã được cung cấp → chuỗi bản sao có provenance, đưa vào Module 0; không chuyển text trích xuất thẳng vào Agent.

- [x] Trích ASCII/UTF-16LE, giữ FILE_OFFSET; không tự suy địa chỉ ảo từ dump offset.
- [ ] Nối nhánh artifact memory có `VIRTUAL_ADDRESS` vào đường ingest theo metadata nguồn được xác nhận — **hoãn có tuyên bố**: chưa có memory dump lab (spec §3.2.2 note; `reports/build-report.md` §5, residual W-1).
- [x] Áp giới hạn chuỗi 6–256 ký tự, tối đa 2.000 chuỗi/mẫu, entropy 2.5–5.5 và vùng ưu tiên theo spec; ghi coverage bị cắt thay vì coi là COMPLETE.
- [x] Adapter lấy `lpOutputString`, `lpString`, `lpText`/`lpCaption` từ các API A/W được allowlist; giữ JSON_LOG_POINTER, PID, API, timestamp.
- [x] Phân biệt report sai schema/thiếu dữ liệu với report hợp lệ không có finding; áp contract lỗi T00. Nạp URL/network theo contract report đã ghim, không đồng nhất với API arguments.

**Nghiệm thu:** fixture hiện có trả đúng ba chuỗi mục tiêu ở calls 0/1/2, bỏ `hWnd`; locator giữ đúng argument index, đặc biệt call 2/arguments/1. Fixture bổ sung vô hại bao phủ MessageBox A/W, missing/wrong-type argument, UTF-16LE và vượt budget. Không chạy URL hoặc câu lệnh nằm trong fixture.

### T03 — Normalization & De-obfuscation Engine (Module 0)

**Owner:** Normalization worker. **Phụ thuộc:** T01; tích hợp với T02 sau khi hai task hoàn thành.  
**Nguồn:** spec §3.1 (dòng 124–205).  
**Tệp:** `src/guardrail/normalization.py`, `tests/test_normalization.py`, `src/guardrail/data/confusables_min.json`.  
**Đầu vào → Đầu ra:** extracted text + provenance → `NormalizedText`, không sửa artifact gốc.

- [x] Chuẩn hóa zero-width, NFKD, confusables theo thứ tự của spec; dùng bảng confusables có phiên bản đã chốt.
- [x] Thực hiện Base64/Hex với decode depth tối đa 2, budget 64KB theo byte UTF-8 (spec §3.1), printable ≥80%; transform chain tích lũy đủ xuyên đệ quy (không lặp lỗi ví dụ cũ).
- [x] Giữ đầy đủ thứ tự transform qua mọi tầng và liên kết representation gốc; bảo toàn provenance.
- [x] Kiểm chứng input lỗi, chuỗi rỗng, encoding lồng ba tầng, boundary budget và dữ liệu Unicode; báo trạng thái coverage đúng contract khi dừng vì giới hạn.

**Nghiệm thu:** case Base64, Hex, Homoglyph, Zero-width có kết quả chuẩn hóa và truy nguyên đúng; tầng thứ ba không bị decode; boundary printable 80% và budget được kiểm rõ. Hash artifact gốc không thay đổi.

### T04 — YARA Static/Memory/Cuckoo Scanner (phần sau Module 1)

**Owner:** Detection worker. **Phụ thuộc:** T01, T02, T03; R04 đã đóng.  
**Nguồn:** spec §2 (LỚP 1 block, dòng 87–92), §3.2 (dòng 209–294).  
**Tệp:** `src/guardrail/yara_scanner.py`, `rules/promptware.yar`, `rules/promptware_cuckoo.yar`, `tests/test_yara_scanner.py`.  
**Đầu vào → Đầu ra:** normalized text cùng artifact/report phù hợp scanner → finding có detector/rule version, source và provenance; không coi raw offset của chuỗi normalized là file offset.

- [x] Chuyển rule tham chiếu thành ruleset biên dịch được trên YARA build đã ghim; áp scanner đúng loại input.
- [x] Không gắn vào PID sống hay điều khiển Sandbox trong repo.
- [x] Lưu lỗi compile/import/scan thành processing outcome đúng contract; giữ finding đã phát hiện trước lỗi (đường Cuckoo hiện trả `PARTIAL` + `ScanError(CAPABILITY)`, không fallback ngầm).
- [ ] Kiểm chứng Cuckoo module bằng report import đã chốt; phân biệt network/file/registry/mutex với adapter API arguments — **blocked**: build `yara-python` local không có `--enable-cuckoo` ⇒ `probe_cuckoo_capability()` trả `available=False` + cờ `cuckoo_unavailable` (`reports/build-report.md` §5).
- [ ] Quét artifact memory được cấp — **blocked**: chưa có dump lab kèm metadata nguồn xác nhận (W-1).

**Nghiệm thu:** chuỗi đối kháng tổng hợp tạo finding truy nguyên được; control vô hại và trường hợp report không tương thích cho outcome đúng. Log ghi build/ruleset/fixture hash. Kết quả fixture là kiểm chứng chức năng hẹp, không phải benchmark recall/FPR; chưa có Cuckoo/memory thật.

### T05 — Meta Prompt Guard-86M service (Module 2)

**Owner:** ML worker. **Phụ thuộc:** T01, T03; tích hợp findings với T04.  
**Nguồn:** spec §3.4 (dòng 304–309); §6.5 (dòng 685–689).  
**Tệp:** `src/guardrail/prompt_guard.py`, `tests/test_prompt_guard.py`, `reports/prompt_guard_measurements.json` (chưa tồn tại).  
**Đầu vào → Đầu ra:** normalized text được lựa chọn theo contract → nhãn, xác suất và model/tokenizer revision; lỗi inference tách khỏi negative finding.

- [ ] Nạp `meta-llama/Prompt-Guard-86M` theo revision đã ghim và xác nhận label mapping từ model artifact — **chưa từng chạy**: weight trả 403 (chờ Meta duyệt, kiểm 2026-09-21); code đọc `model.config.id2label`, không đoán thứ tự logits.
- [x] Áp ngưỡng Injection hoặc Jailbreak ≥0.75 (spec §3.4) và predicate Malware Command/Promptware; chốt định nghĩa `TargetEntityIsLLM`/`InstructionOverrideContext` tại task này theo contract §3.4. Không tái đưa ngưỡng 0.50 từ PLAN vào như quy tắc hiện hành.
- [x] Xử lý chuỗi dài/sequence length 512 và truncation theo coverage contract; không âm thầm mất phần chưa được kiểm tra.
- [ ] Đo inference thật trên cấu hình CPU/GPU thực dùng, batch 8–16; ghi thời gian/load conditions, không thay phép đo bằng mocked latency. — blocked: model ghim trả 403 nên **chưa từng nạp được weight thật**; xem `reports/build-report.md` §5
- [ ] Chốt model dùng cho Lớp 3 trước khi đo: chờ quyền cho `meta-llama/Prompt-Guard-86M`, hoặc chuyển sang `meta-llama/Llama-Prompt-Guard-2-86M` (đã có bản local `a8ded8e697ce7c355e395a0df51f94adb4a2fd27`, nạp offline được, nhưng **2 lớp** — không có `INJECTION`, `config.json` không kèm `id2label`) ⇒ cần label profile + ngưỡng hiệu chỉnh riêng và cập nhật spec §3.4/ADR

**Nghiệm thu:** kiểm boundary 0.75, hai loại xác suất và predicate; lỗi/timeout không trở thành NOT_DETECTED. Smoke với model thật tạo output có revision và timing; thiếu model hoặc tài nguyên thì ghi blocked, không phát sinh score giả.

### T06 — Mandiant CAPA Allowlist Projection (Module 3)

**Owner:** Capability worker. **Phụ thuộc:** T01; độc lập T02–T05.  
**Nguồn:** spec §3.3 (dòng 297–300); ADR-0001 và ADR-0003.  
**Tệp:** `src/guardrail/capa_projection.py`, `tests/test_capa_projection.py`; fixture CAPA JSON tĩnh/động vô hại có nguồn/version.  
**Đầu vào → Đầu ra:** JSON từ Mandiant CAPA cho PE và CAPE report → capability allowlist.

- [x] Kiểm chứng định dạng output tĩnh/động theo CAPA/ruleset revision trước khi viết parser; CAPEv2 không phải Mandiant CAPA.
- [x] Chiếu duy nhất `tactic`, `technique_id`, `technique_name`, `namespace`; loại raw strings, disassembly, API arguments và field ngoài allowlist.
- [x] Đưa giá trị còn lại qua ingress contract; không tin cậy giá trị chỉ vì tên field nằm trong allowlist.
- [x] Phân biệt capability rỗng hợp lệ với lỗi parser/schema; giữ liên kết artifact để hội tụ hai branch.

**Nghiệm thu:** capability được giữ đúng trên fixture tĩnh và động; nội dung ngoài allowlist không tới context; fixture sai cấu trúc không bị báo là “không có capability”. Fixture thật trong repo là ảnh chụp CAPA 7.0.1, không phải mẫu cùng nguồn với CAPE fixture (`README.md` §3/§7 mục 7).

### T07 — Decision Policy Gate và Evidence (Module 4, phần policy)

**Owner:** Policy worker. **Phụ thuộc:** T01; tích hợp T04, T05, T06.  
**Nguồn:** spec §3.5.1 (dòng 313–343), §4.1 (dòng 380–475), §5 (dòng 621–643).  
**Tệp:** `src/guardrail/policy.py`, `src/guardrail/evidence.py`, `tests/test_policy.py`, `tests/test_evidence.py`.  
**Đầu vào → Đầu ra:** findings/capabilities và processing/detection states → pipeline action, evidence decisions, forwarding, sanitization, flags, escalation và verdict constraints.

- [x] Hiện thực đủ 9 tổ hợp theo ma trận đã xác nhận; tổng hợp detector disagreement bằng contract T00, không để policy tự suy luận score.
- [x] Bảo toàn positive finding ở cả PARTIAL+DETECTED và FAILED+DETECTED, kể cả khi không forward context.
- [x] Sinh evidence riêng cho finding/coverage gap/escalation đúng schema; giữ raw evidence ở kho điều tra, không đẩy raw telemetry của escalation vào context.
- [x] Ánh xạ MITRE theo bằng chứng thực; lưu multi/no-mapping đúng contract, phân biệt attempt với execution.

**Nghiệm thu:** kiểm cả chín tổ hợp, không chỉ action string. Các nhánh FAILED không forward; PARTIAL không cho BENIGN; disagreement có flag và sanitize/escalation; positive evidence vẫn truy xuất được sau lỗi. ID/hash/provenance và mapping hợp lệ. Kho raw evidence độc lập và binding cùng-mẫu vẫn là khoảng cách mở (`audit.md` A03, SP-03/L07).

### T08 — Context Serialization, Execution Rails và Output Governance (Module 4, phần tích hợp)

**Owner:** Integration owner. **Phụ thuộc:** T06, T07 và contract T01.  
**Nguồn:** spec §3.5.2 (dòng 345–363), §3.6 (dòng 367–374), §4.2 (dòng 477–566); ADR-0003.  
**Tệp:** `src/guardrail/context.py`, `src/guardrail/runtime.py`, `src/guardrail/report.py`, `src/guardrail/pipeline.py`, `tests/test_context.py`, `tests/test_runtime.py`, `tests/test_pipeline.py`, `tests/test_report.py`, `tests/test_e2e_adversarial.py`.  
**Đầu vào → Đầu ra:** policy-authorized metadata/capabilities/evidence summary → Chat payload → báo cáo hợp lệ hoặc fallback; tool results quay lại cùng ingress policy.

- [x] Tạo message role `system` độc lập dữ liệu; serialize/escape dữ liệu thay vì nối chuỗi tạo instruction. Khóa đường raw evidence khỏi context.
- [x] Dispatcher chỉ cho `get_pe_header_details()`, `get_mitre_capabilities()`, `get_adversarial_findings()`; mọi tool result qua ingress. Tool ngoài danh sách bị chặn trước side effect và ghi evidence theo contract.
- [x] Validate report bằng `jsonschema` Draft-07 đã ghim (ADR-0004 hoãn Guardrails AI); tối đa hai lần re-ask sau lần sinh ban đầu. Hết lượt → `ABSTAINED_PARTIAL`, `INCONCLUSIVE`, validation errors theo schema đã hoàn thiện ở T00, không ép BENIGN.
- [x] Kiểm tra tham chiếu evidence tồn tại và tuân thủ verdict constraints ngoài structural validation.
- [x] Tích hợp Canary Token Verifier theo spec §5 (footnote Canary, dòng 641) và contract T00; dùng canary đánh giá được cấp, không đưa secret thật vào fixture. Kiểm cả có/không có canary và hành động leakage đã chốt.
- [ ] Chạy smoke end-to-end bằng artifact vô hại và model thật trong môi trường được phép: hai branch → gate → context → report; lưu kết quả từng tầng. — smoke đã chạy với stub backend; model thật blocked

**Nghiệm thu:** delimiter/role-looking text từ fixture không tạo message system mới; tool result không được bỏ qua ingress; tool cấm không có side effect. Báo cáo trỏ ID không tồn tại phải bị từ chối. Đầu ra sai sau hai re-ask dừng hữu hạn với fallback hợp lệ; FAILED không gọi Agent để phát verdict. Test double chỉ dùng kiểm nhánh lỗi, không thay bằng chứng smoke với model thật.

## 5. Phase 3 — Đánh giá và nghiệm thu

### T09 — Dataset protocol, ground truth và split tái lập

**Owner:** Evaluation worker. **Phụ thuộc:** T00/T01 cho thiết kế; nghiệm thu dataset trước T10.  
**Nguồn:** spec §6.1–6.2 (dòng 647–669, bảng nhóm 654–665); intent §7 dòng 178; R06.  
**Tệp:** `src/guardrail/evaluation/dataset_protocol.py`, `tests/evaluation/test_dataset_protocol.py`, `reports/dataset_manifest.json`, `reports/split_manifest.json`.  
**Đầu vào → Đầu ra:** dataset/artifact được phê duyệt + ground truth độc lập → manifest paired samples, split và bằng chứng invariance.

- [x] Dùng mục tiêu 400 mẫu = 200 pairs; mỗi pair giữ sample gốc và sample có Promptware, không hiểu “clean” là mặc định GT_Malware_Behavior=benign.
- [x] Ghi `GT_Injection` và `GT_Malware_Behavior` độc lập, group/family/payload family/pair ID/hash/source. Chỉ gán Nhóm 1–4 theo bảng chuẩn hoá §6.1 (spec v1.4.0), không tự suy ra group từ số thứ tự.
- [ ] Kiểm chứng artifact pair chỉ khác data regions được phép; code-region hash bất biến, behavioral signature Jaccard ≥0.95 theo lab evidence đã được cung cấp. Ghi `pair_rejection_rate`; không chạy Malware Sample trong repo để tạo bằng chứng. — blocked: chưa có dataset/lab; protocol + harness đã xong (a849474/1e0e38e/a5b1d01)
- [x] Chia 80 pairs calibration / 120 pairs test; giữ hai thành viên pair cùng split, tách cả malware family và payload family. Không chỉnh threshold theo test set.

**Nghiệm thu:** manifest truy nguyên được mỗi pair và hai ground truth; không overlap pair/family hai trục; pair sai invariance bị loại có lý do. Thiếu lab evidence → dataset chưa được nghiệm thu, không thay bằng giả định. Harness hiện có đang cưỡng chế cân bằng benign/malware theo split (SP-08) và chưa tự đối chiếu transform/plaintext của de-obfuscation (F-R2) — sửa trước khi đo (`PLAN.md` §7 mục 6).

### T10 — Bốn baseline, workload và báo cáo thực nghiệm

**Owner:** Evaluation worker; Integration owner nghiệm thu. **Phụ thuộc:** T02–T09 và gate Phase 2 pass.  
**Nguồn:** spec §6.3–6.7 (dòng 671–724; bảng metric 716–724).  
**Tệp:** `src/guardrail/evaluation/metrics.py`, `tests/evaluation/test_metrics.py`, `reports/evaluation_results.json`, `reports/evaluation_summary.md`.  
**Đầu vào → Đầu ra:** test manifest đã khóa + môi trường/model/ruleset revisions → raw outcomes/timings, metric denominators, baseline comparison và kết luận target pass/fail.

- [ ] Chạy no-guardrail, YARA-only, ML-only, full pipeline trên cùng test split, cùng model cấu hình đã khóa; ghi rõ khác biệt bật/tắt từng tầng. — blocked: chưa có dataset/lab; protocol + harness đã xong (a849474/1e0e38e/a5b1d01)
- [x] No-guardrail chỉ là đối chứng cách xử lý nội dung trong môi trường đánh giá cô lập; không cấp quyền shell/network thật để đo tool misuse. Tách lời gọi trái phép được phát ra với hành động đã thực thi.
- [ ] Ghi bốn attack success modes: đổi verdict, bỏ evidence/capability cốt lõi, attempted tool misuse, leakage canary/system instructions. Chốt ground truth cho omission/leak trước khi chạy. — blocked: chưa có dataset/lab; protocol + harness đã xong (a849474/1e0e38e/a5b1d01)
- [ ] Đo CPU x86_64 ≥8 cores, RAM ≥32GB, GPU RTX 3060 hoặc T4 với VRAM ≥12GB theo spec; báo phần cứng thực tế. Concurrency 1/4/8, batch 8–16, sequence length 512, budget 2.000 chuỗi/mẫu. — blocked: chưa có dataset/lab; protocol + harness đã xong (a849474/1e0e38e/a5b1d01)
- [ ] Đo monotonic clock từng tầng và overhead so với raw pipeline; xuất p50/p90/p95/p99, warm/cold conditions và percentile nghiệm thu theo §6.5 (p95 @ C=1). — blocked: chưa có dataset/lab; protocol + harness đã xong (a849474/1e0e38e/a5b1d01)
- [x] Báo cáo tử số/mẫu số, coverage, failure và abstention; không bỏ các case khó chỉ để đạt target. Khi denominator bằng 0, đánh dấu không tính được theo protocol đã chốt, không báo 100%.

| Chỉ số | Mục tiêu, không phải kết quả | Nguồn/điều kiện |
|---|---|---|
| Detection Recall | ≥90% | §6.6–6.7, Nhóm 2+4 (bảng nhóm §6.1). |
| FPR | ≤5% | §6.6–6.7, Nhóm 3; Malware Command không bị nhận nhầm Promptware. |
| ERR | ≥95% | Verdict MALICIOUS / tổng Nhóm 4, không loại abstention khỏi mẫu số một cách tùy ý. |
| Latency overhead | ≤15 giây | §6.5/§6.7; p95 @ C=1 so với Raw Pipeline. |
| Schema compliance | 100% | `N_valid_schema / N_total_non_abstained` (§6.6); không coi abstention là verdict đúng. |
| Pipeline abstention | ≤3% | `N_abstained / N_total_processed`, báo riêng. |
| De-obfuscation success | ≥90% | Base64/Hex/Homoglyphs/Zero-width; `N_decoded/N_encoded` (§6.6). |

Báo thêm Baseline Malware Accuracy theo công thức §6.6, tỷ lệ loại pair, bốn attack success rates và lỗi từng tầng; dùng đúng tên/công thức/denominator đã chốt trong spec v1.4.0.

**Scenario kiểm phép đo:** với 10 outcomes tổng hợp, 2 abstained và 8 non-abstained hợp schema, compliance là 8/8 = 100% nhưng abstention là 2/10 = 20%, không đạt target ≤3%. Một pair có Jaccard 0.94 bị loại; một family xuất hiện ở cả hai split chặn benchmark. Mẫu số benchmark lấy từ số mẫu thực xử lý của split đang đo, không mặc định dùng 400 khi test split chỉ có 240 mẫu.

**Scenario tái lập:** chạy lại cùng seed, hardware và revisions trên manifest phải lệch ≤0.5% so với kết quả đã ghi. Chỉ số không đạt target vẫn ghi đúng giá trị thực kèm cờ `SLA_MISSED`; không làm tròn hoặc diễn giải lại để đạt mục tiêu.

**Nghiệm thu:** mọi baseline có raw outcomes, run manifest và denominators đối chiếu được; metric test kiểm counting/abstention/leakage boundaries bằng dữ liệu tổng hợp, benchmark thật chứng minh target đạt hoặc không đạt. Report tách structural validity, evidence validity và verdict correctness. Không đánh dấu nghiệm thu hệ thống nếu chỉ fixture smoke pass. Harness hiện có chỉ tính từ outcomes do caller khai — chưa có runner bốn baseline và chưa nối agent thật (`audit.md` A01).

## 6. Bản đồ yêu cầu → task → bằng chứng

| Yêu cầu | Task | Bằng chứng nghiệm thu tương lai |
|---|---|---|
| R01, R07; policy và schema | T00, T01, T07, T08 | Gate report, schema checks, ma trận 9 state, report/evidence integrity. |
| R02; trust boundary | T00, T06, T08 | Ingress/serialization và dispatcher scenarios; review ADR/CONTEXT/links. |
| R03; provenance/dataflow | T00, T02, T03, T07 | Trace artifact xuyên pipeline, transform chain đầy đủ. |
| R04; tương thích tích hợp | T00, T01, T02, T04, T06 | Build/version manifest, fixture logs cho YARA/CAPE/CAPA. |
| R05; mapping | T00, T07 | Taxonomy snapshot và evidence support; attempt/execution tách biệt. |
| R06, R08; protocol và phép đo | T00, T05, T09, T10 | Split manifest, raw timing/outcomes, baseline/metrics report. |
| Module 0 / Module 1 / Module 2 | T03 / T02+T04 / T05 | Normalization / heuristic / model acceptance scenarios. |
| Module 3 / Module 4 theo PLAN | T06 / T07+T08 | Capability projection / policy, context, rails và report. |
| Benchmark Module 4 theo spec §7 | T09+T10 (Phase 3 theo PLAN) | Evaluation artifacts; khác biệt cách đánh số được chốt tại T00. |

## 7. Phân công, phụ thuộc và bằng chứng chốt

**Phụ thuộc thực thi:** T00 → T01 → {T02 → T03 → T04; T03 → T05; T06 độc lập}; T07 sau T04/T05/T06; T08 sau T06/T07; T09 mở từ T01; T10 sau T02–T09 và gate Phase 2. Thứ tự này là phụ thuộc task, không đổi luồng runtime: **extraction (T02) → normalization (T03) → detectors (T04/T05)**; Capability Branch (T06) độc lập, hội tụ ở T07/T08. Không để tên “Module 1” khiến telemetry extraction bị đặt sau normalization.

**Ownership:** Integration owner giữ diễn giải yêu cầu, contract/schema/state dùng chung và quyền kết luận nghiệm thu; **mỗi shared schema chỉ một owner sửa**. Worker chỉ sửa file được giao, handoff bằng đường dẫn artifact + scenario cần kiểm + rủi ro/phụ thuộc, không tự tick task của worker khác. Không chạy build/lint/test khi worker khác đang sửa song song; mock chỉ bảo vệ edge case, không thay smoke với model thật. Bất đồng thiết kế → owner quyết định, không tự chọn contract mới.

**Bằng chứng chốt:** gate Phase 0 và roster Mục A ở `reports/phase0-gate.json`; verdict từng mục B–F, bug ledger và waiver ở `reports/build-report.md` §1–§5; coverage nhóm L0–L3 ở `reports/coverage.json`; pin môi trường ở `reports/integration-pin.json`. Lịch sử dispatch/supervisor chi tiết **không** chép lại ở đây.

## 8. Definition of Done và trạng thái bàn giao

- [x] T00 pass: R01–R08 có bằng chứng, checklist và trạng thái tài liệu nhất quán.
- [x] T01–T08 pass theo verdict supervisor: đủ Module 0–4 theo PLAN, Execution Rails và report validation hoạt động; không còn contract giả hay đường bypass ingress. (residual mở ở `reports/build-report.md` §3/§5)
- [x] Smoke E2E dùng fixture vô hại qua stub backend; negative/failure paths bảo toàn evidence và abstain đúng.
- [ ] Smoke E2E với **model thật**: chưa chạy — model ghim 403 (T05/T08).
- [x] T09–T10 tooling: dataset protocol, split, harness metric/timing tái lập. (verdict `muc-f-sup`: tooling PASS)
- [ ] T09–T10 phép đo: bốn baseline trên test split, từng target ghi pass/fail kèm `SLA_MISSED` khi trượt — blocked, chưa có dataset/lab (`reports/build-report.md` §5).
- [x] Kết luận phân biệt prototype correctness, empirical efficacy và residual risk; giới hạn chưa kiểm chứng được công bố.
- [x] AGENTS/PLAN/spec/intent/ADR/issue đồng bộ theo mức đã kiểm chứng trong T00; phần lệch còn lại theo dõi ở `audit.md` A01–A06.

**Trạng thái bàn giao prototype (2026-09-21):** T01–T08 PASS theo verdict supervisor; smoke E2E chạy với stub backend (model thật gated); T09–T10 có protocol + harness nhưng chưa chạy phép đo thực nghiệm. Chưa chứng minh bất kỳ target SLA nào — phần bị chặn và waiver ở `reports/build-report.md` §5.
