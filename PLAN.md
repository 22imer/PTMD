# Phase 2 Prototype Plan — Guardrail Malware Agent

**Status (2026-09-21):** Phase 2 — đã có prototype T01–T08 theo verdict lịch sử, còn lỗi tích hợp và nghiệm thu model/môi trường; Phase 3 có protocol/harness, **chưa có benchmark thật**. Audit định hướng: `audit.md`.

**Related Documents:**
- `specs/guardrail_malware_agent_spec.md` — spec kỹ thuật hiện hành; v1.4.0 (T00 fix 2026-09-19) supersedes review snapshot v1.2.0.
- `intent/research_pre_validate.md` — research intent v1.2.1 (đồng bộ diagram 2026-09-19).
- `CONTEXT.md` — ubiquitous language.
- `docs/adr/0001-separate-capa-from-capev2.md`, `docs/adr/0002-tag-as-evidence-over-hard-block.md`, `docs/adr/0003-passive-consumer-agent.md` — quyết định kiến trúc.
- `links.md` — nguồn tham khảo và taxonomy.
- `issues/issue_2026-09-18_review_intent_specs.md` — review intent/spec ban đầu.
- `issues/issue_2026-09-19_unresolved_spec_review.md` — gate R01–R08 và tiêu chí đóng.
- `audit.md` — đối chiếu intent → spec → code → bằng chứng; backlog ưu tiên ở §7 dưới đây không thay contract spec.

## 1. Mục tiêu & phạm vi

Kế hoạch này đưa đề tài từ spec sang prototype và kiểm chứng giả thuyết: giảm tấn công IPI lên agent phân tích Windows PE, đồng thời đo độ trễ và chất lượng phân tích nền (intent §1.2). Phase 0 đã PASS; prototype được phép xây dựng nhưng PASS của wave code không thay nghiệm thu tích hợp hoặc hiệu quả thực nghiệm. Giữ hai nhánh detection/capability, Tag-as-Evidence và Passive Consumer Agent; không mở sang production, tự động sửa mã độc hoặc agent điều khiển sandbox.

**Cách đọc trạng thái:** `reports/build-report.md` ghi verdict theo wave; `README.md` §7 và các issue ghi lỗi còn mở; `audit.md` đối chiếu mức bằng chứng hiện tại. Số Module 0–4 dưới đây là cách chia công việc của PLAN, không phải số Lớp 0–5; “Module 4 benchmark” của spec §7 được theo dõi bằng T09/T10 ở Phase 3, không bị bỏ khỏi phạm vi.

## 2. Phase 0 — Spec Hardening Gate (Cổng chặn)

Quy tắc gate: **Phase 2 không được khởi động cho tới khi tất cả R01–R08 đóng và issue 2026-09-19 được tái kiểm tra**. Repo đánh dấu issue Resolved/Closed (spec v1.3.0); tái kiểm tra T00 trên spec v1.4.0 (2026-09-19) xác nhận 8/8 CLOSED — gate PASS.

Kết quả T00 (2026-09-19): audit v1 8/8 PARTIAL → BLOCK; áp fix D01–D18 (spec v1.4.0); tái kiểm tra v2 8/8 CLOSED → **gate PASS**. Chi tiết: `reports/phase0-gate.json`.

| ID | Nội dung cần sửa | Tài liệu tác động | Tiêu chí hoàn thành |
|---|---|---|---|
| R01 | Thống nhất policy gate & evidence action vocabulary; `PARTIAL+DETECTED` bảo toàn finding, chốt sanitization/escalation/detector-disagreement/hết-re-ask. | spec §3.5, §4.1 | Issue §6 R01: từng tổ hợp processing/detection state có hành động rõ ràng; positive finding được bảo toàn; sanitization, escalation, detector disagreement và fallback có contract nhất quán. |
| R02 | Áp trust boundary nhất quán; contract cho tool-returned data; gỡ mọi tuyên bố an toàn ở mức tuyệt đối. | spec §1.1/§3.5, `docs/adr/0002`, `CONTEXT.md`, `links.md` | Issue §6 R02: tool-returned data được bao phủ bởi ingress policy; spec, glossary, ADR và links không còn cam kết an toàn bằng escaping/Spotlighting như một bảo đảm tuyệt đối. |
| R03 | Làm rõ đường telemetry → normalization → findings; provenance cho file/memory/log. | spec §2, §3.1, §3.2.2 | Issue §6 R03: có đường dữ liệu rõ ràng từ telemetry extraction qua normalization đến findings; provenance hỗ trợ file, memory và log. |
| R04 | Ghim phiên bản YARA/CAPE + report schema; bổ sung fixture vô hại và kết quả tương thích; mô tả đúng phạm vi Cuckoo module. | spec §3.2.2 | Issue §6 R04: phiên bản tích hợp/report schema được ghim; có fixture vô hại và kết quả kiểm chứng tương thích; phạm vi Cuckoo module được mô tả đúng. |
| R05 | Đồng bộ mapping MITRE ở mọi tài liệu; phân biệt attempt/execution. | spec §5, `links.md`, `docs/adr/0002` | Issue §6 R05: mapping trong mọi tài liệu liên quan thống nhất với taxonomy có phiên bản; phân biệt attempt và execution bằng evidence. |
| R06 | Bổ sung paired samples, split chống leakage, baselines, định nghĩa attack success. | spec §6 | Issue §6 R06: có paired samples, split chống leakage, các baseline và định nghĩa attack success cho mục tiêu đã chọn. |
| R07 | Evidence transform chain, multi/no ATLAS mapping, liên kết final report, quan hệ policy vocabularies. | spec §4 | Issue §6 R07: evidence hỗ trợ transform provenance, multi/no-mapping và liên kết final report; policy vocabularies có quan hệ rõ ràng. |
| R08 | Định nghĩa workload/hardware/batch/concurrency/percentile; đo abstention riêng. | spec §3.4, §6.3 | Issue §6 R08: các mục tiêu có workload/hardware/batch/concurrency/percentile và cách tính tương ứng; schema compliance và abstention được đo riêng. |

**Exit criteria Phase 0:** toàn bộ checklist §6 issue 2026-09-19 tick; issue chuyển trạng thái sau tái kiểm tra.

## 3. Phase 2 — Xây dựng prototype (Module 0–4)

### Module 0 — Normalization & De-obfuscation Engine

- **Mục tiêu:** chuẩn hóa và gỡ obfuscation trên bản sao chuỗi trích xuất, giữ provenance về nguồn.
- **Nguồn spec:** spec §3.1 (dòng 124–205).
- **Đầu vào → Đầu ra:** extracted text bản sao, giữ offset/provenance → `NormalizedText` gồm NFKD, strip zero-width, confusables, bounded decode depth 2 / 64KB / printable ≥80%.
- **Phụ thuộc:** R03 vì đường dữ liệu telemetry/extraction phải rõ trước khi triển khai.
- **Tiêu chí hoàn thành:** xử lý đúng các case Base64, Hex, Homoglyph, Zero-width; giữ liên kết offset/provenance để truy vết finding.
- **Hiện trạng:** code T03 PASS theo wave; chưa đo de-obfuscation trên dataset thật.

### Module 1 — YARA Static + Telemetry Ingestion Adapter

- **Mục tiêu:** phát hiện promptware từ PE strings và telemetry CAPEv2 qua luật YARA + adapter API arguments.
- **Nguồn spec:** spec §3.2 (dòng 209–293).
- **Đầu vào → Đầu ra:** PE strings + CAPEv2 report → findings + `SANDBOX_API_LOG` records (enum §4.1).
- **Phụ thuộc:** Module 0; R04 vì cần fixture/phiên bản/report schema.
- **Tiêu chí hoàn thành:** rule biên dịch; adapter trích API args mục tiêu; chạy trên fixture R04 mà không cần thực thi mã độc sống.
- **Hiện trạng:** code T02/T04 có kiểm chứng offline; còn coverage ingestion (L01), giới hạn byte/provenance (L04/L05), Cuckoo unavailable và đường memory chưa nghiệm thu. Điều kiện môi trường không miễn trừ lỗi logic.

### Module 2 — Meta Prompt Guard-86M service

- **Mục tiêu:** phân loại chuỗi nghi vấn bằng Meta Prompt Guard-86M và phát tín hiệu neural guardrail.
- **Nguồn spec:** spec §3.4 (dòng 304–309).
- **Đầu vào → Đầu ra:** chuỗi nghi vấn → nhãn + xác suất theo ngưỡng 0.75 và predicate §3.4; tổng hợp lỗi/bất đồng theo §3.5.1.1. Không có ngưỡng dưới 0.50; T00 đã đóng contract.
- **Phụ thuộc:** Module 0.
- **Trạng thái model (2026-09-21):** model tham chiếu `meta-llama/Prompt-Guard-86M` (revision ghim `1209add6…7b03`) trả **403** — chờ Meta duyệt, pin giữ nguyên. `meta-llama/Llama-Prompt-Guard-2-86M` @ `a8ded8e6…2fd27` tải được và đã có bản local (nạp offline OK) nhưng **chưa nối** vào Lớp 3: 2 lớp, không có nhãn `INJECTION`, artifact không kèm `id2label`. Chi tiết: `README.md` §7 mục 8, `reports/build-report.md` §5.
- **Hiện trạng tích hợp:** SP-05 còn mở — Prompt Guard chỉ nhận telemetry, chưa nhận static strings; SP-06 — cắt `prompt_guard_budget` chưa phản ánh coverage. Gỡ quyền model không tự sửa hai lỗi này.
- **Tiêu chí hoàn thành:** service phân loại được; đo latency thực trên CPU/GPU và gắn cấu hình đo R08.

### Module 3 — Mandiant CAPA parser (Allowlist Projection)

- **Mục tiêu:** tạo capability branch không đưa raw free-text từ CAPA/CAPE vào agent context.
- **Nguồn spec:** spec §3.3 (dòng 297–300).
- **Đầu vào → Đầu ra:** `capa -j` PE tĩnh và CAPE report → chỉ `tactic/technique_id/technique_name/namespace`, tước free-text.
- **Phụ thuộc:** độc lập với Module 0–2 trong Capability branch.
- **Tiêu chí hoàn thành:** projection loại bỏ raw strings và chú thích/log tự do, giữ capability có cấu trúc.
- **Hiện trạng:** code T06 PASS với output CAPA producer thật; việc bảo toàn chất lượng phân tích và ràng buộc cùng-mẫu giữa các nguồn vẫn chưa được chứng minh bằng benchmark.

### Module 4 — Decision Policy Gate + Context Serialization

- **Mục tiêu:** hợp nhất detection branch và capability branch thành policy action, Spotlighting Chat payload, evidence JSON và final report JSON.
- **Nguồn spec:** spec §3.5 (dòng 313–363); spec §4 (dòng 378–619).
- **Đầu vào → Đầu ra:** findings + capabilities + processing/detection state → policy action + Spotlighting Chat payload + evidence/report JSON.
- **Phụ thuộc:** Module 0–3; R01/R07 vì vocabulary/schema phải thống nhất.
- **Tiêu chí hoàn thành:** 9 tổ hợp state cho hành động nhất quán với schema; report tham chiếu evidence tồn tại.
- **Hiện trạng:** T07/T08 PASS theo wave, không phải nghiệm thu đầy đủ: L02/L03 (report identity/cờ/fallback), SP-03 (kho raw evidence) và smoke model thật còn mở. Validator prototype dùng `jsonschema` theo ADR-0004, không claim đã tích hợp Guardrails AI.

## 4. Phase 3 — Đánh giá & nghiệm thu

Phase 3 đã có protocol/harness; **phép đo nghiệm thu chưa được mở**. Chạy protocol 4 nhóm của spec §6.1 sau các gate ở §7: 400 mẫu/200 pairs, hai ground truth độc lập; 80 pairs calibration và 120 pairs test, tách cả malware family và payload family. Bốn baseline: no-guardrail, YARA-only, ML-only và full pipeline; agent thật dùng cùng cấu hình đã khóa, không dùng verdict của `SimulatedAgent`.

Báo đủ metric spec §6.6–§6.7: Detection Recall ≥90%, FPR ≤5%, ERR ≥95%, overhead p95 @ C=1 ≤15s, Schema compliance 100%, Pipeline Abstention ≤3%, De-obfuscation ≥90%; thêm Baseline Malware Accuracy, bốn attack success modes và pair rejection rate. Đo C=1/4/8, p50/p90/p95/p99 với workload/hardware/batch theo §6.5. Mẫu số 0 báo `N/A`; mọi ngưỡng là target, không phải kết quả. Chỉ hiệu chỉnh trên calibration, không sửa ngưỡng theo test.

## 5. Trình tự & phụ thuộc

Phase 0 đã mở Phase 2. Trong detection branch, Module 0 → Module 1 → Module 2; capability branch Module 3 độc lập; hai nhánh hội tụ ở Module 4. Có thể chuẩn bị protocol/dataset và gỡ chặn môi trường song song với sửa lỗi offline, nhưng **chỉ chạy benchmark nghiệm thu khi gate tích hợp, model, agent thật và dataset đều đạt**. Kết nối agent thật là điều kiện trước phép đo, không phải bước sau khi đã xuất số liệu.

## 6. Điều kiện nghiệm thu tổng thể

- [x] Phase 0 R01–R08 đóng sau tái kiểm tra — `reports/phase0-gate.json`, gate PASS ngày 2026-09-19.
- [ ] Module 0–4 đạt cả nghiệm thu tích hợp; đóng các lỗi ảnh hưởng phép đo và có bằng chứng model/dynamic thật, không chỉ verdict wave.
- [ ] Phase 3 có raw outcomes/timings, manifest và báo cáo đủ baseline/metric; target đạt hoặc không đạt đều ghi trung thực.
- [ ] Các câu hỏi nghiên cứu intent §6 có kết quả hoặc được ghi rõ chưa trả lời; không suy hiệu quả CAPA/Tag-as-Evidence riêng lẻ từ benchmark toàn pipeline.
- [ ] Tài liệu trạng thái thống nhất theo mức bằng chứng; `implemention.md` còn các checkbox/câu tiền triển khai cần đối soát (`audit.md` A06).

## 7. Backlog sau audit định hướng (2026-09-21)

Ưu tiên là khép khoảng cách với đề tài, không thêm UI/server/framework hoặc tăng test count như một mục tiêu. Các mục dưới đây **chưa thực thi trong đợt audit tài liệu**; giữ ID issue cũ, không tự đóng bằng cách sửa mô tả.

| Thứ tự / owner | Công việc và nguồn | Điều kiện hoàn thành |
|---|---|---|
| 1 — Integration + Detection | L01–L05 (`issues/issue_2026-09-19_readme_known_limitations.md`): coverage, report identity/cờ, fallback finding, trần byte, provenance chuỗi trùng. | Scenario lỗi trước/sau chứng minh coverage không bị nâng giả lên COMPLETE; report không đổi hash/bỏ cờ; finding dương còn trong fallback; budget/provenance truy nguyên được. Dùng enum spec `DETECTED`, `TRUNCATED_ARTIFACT_FLAG`, không chép tên đề xuất sai trong issue cũ. |
| 2 — Detection + Integration | SP-05/SP-06 (`issues/issue_2026-09-20_full_project_review_new_findings.md`): nối static và telemetry vào Prompt Guard, chốt phân bổ budget. | Cả hai nguồn được detector xử lý với provenance đúng; cắt budget ghi coverage không đầy đủ. Kiểm cả nhiều chuỗi cùng khớp một rule qua dedupe/predicate (rủi ro đọc tĩnh ở `audit.md` A02). Có thể kiểm logic offline trong khi chờ model. |
| 3 — Integration | SP-03 + L07: kho raw evidence độc lập, hash và binding cùng-mẫu cho PE/CAPE/CAPA; thiết kế lưu trữ theo ràng buộc lab, không tự thêm dịch vụ. | Truy hồi raw evidence qua hash/provenance bên ngoài context; fixture cùng-mẫu và trường hợp mismatch có bằng chứng xử lý; giữ sample gốc bất biến. |
| 4 — ML + chủ lab (song song 1–3) | Chốt model Lớp 3: chờ quyền cho pin hiện hành, hoặc phê duyệt migration PG2 bằng ADR/spec + label profile + pin + calibration. | Smoke thật và `reports/prompt_guard_measurements.json` chứa revision, sha256 artifact, ngày, label mapping, workload và timing. PG2 nạp được ngoài pipeline không đóng T05/T08. |
| 5 — Detection + chủ lab (song song 1–4) | YARA có Cuckoo; ingest memory dump được lab cung cấp với provenance `VIRTUAL_ADDRESS` (SP-10/W-1). | Positive Cuckoo report → evidence E2E có provenance hợp lệ (rủi ro đọc tĩnh ở `audit.md` A04), không chỉ import/scan; dump hash + parent PE hash + địa chỉ/PID xác nhận, trace xuyên pipeline. Không thực thi/unpack sample trong repo. Thiếu nhánh nào thì chưa claim full static+dynamic. |
| 6 — Evaluation + chủ lab | T09: duyệt paired dataset, invariance và split; xử lý F-R2/F-R11/F-R15 trong ledger, cùng SP-08 về ràng buộc origin-balance ngoài spec. | `reports/dataset_manifest.json`, `reports/split_manifest.json`; 200 pairs, code-region hash bất biến, Jaccard ≥0.95, rejection log, không leakage hai trục; metadata encoding và outcome đủ kiểm metric §6.6. Không âm thầm thêm điều kiện chia tập ngoài spec. |
| 7 — Integration + Evaluation | Nối agent thật và đường chạy bốn baseline trước T10; chuẩn bị run manifest của môi trường thực tế. | Smoke vô hại qua agent thật, revision/cấu hình tái lập; cùng test split/agent settings; no-guardrail chỉ bỏ lớp xử lý nội dung, không cấp shell/network tool thật. `SimulatedAgent` chỉ dùng dev/smoke. |
| 8 — Evaluation + người review | T10: chạy bốn baseline khi 1–7 đạt, xuất kết quả; đối chiếu câu hỏi intent §1.2/§6. | `reports/evaluation_results.json`, `reports/evaluation_summary.md`, raw outcomes/timings và denominators đối soát được; báo target pass/fail, abstention và residual risk. Hiệu quả riêng CAPA và bảo toàn thông tin Tag-as-Evidence cần phép đo được chốt hoặc ghi rõ còn chưa trả lời. |

**Gate trước benchmark:** người review xác nhận bằng chứng cho 1–7; `reports/environment.json` hiện chỉ là snapshot T01, không thay run manifest cho model/YARA/agent/hardware thực dùng. Waiver môi trường cho prototype không phải waiver cho nghiệm thu hiệu quả.

**Đồng bộ hồ sơ:** `PLAN.md`/`AGENTS.md` được cập nhật trong audit này. Đối soát tiếp các dòng lịch sử/checkbox gây hiểu nhầm ở `implemention.md` và nhãn “final” của snapshot test cũ trong `reports/build-report.md`; bảo toàn lịch sử, không sửa spec để hợp thức hóa code. Khi trạng thái model/môi trường thực sự đổi, đồng bộ trọn bộ theo `AGENTS.md`.
