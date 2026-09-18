# Phase 2 Prototype Plan — Guardrail Malware Agent

**Status:** Draft — Plan Phase (AI SDLC)

**Related Documents:**
- `specs/guardrail_malware_agent_spec.md` — spec kỹ thuật hiện hành; v1.4.0 (T00 fix 2026-09-19) supersedes review snapshot v1.2.0.
- `intent/research_pre_validate.md` — research intent v1.2.1 (đồng bộ diagram 2026-09-19).
- `CONTEXT.md` — ubiquitous language.
- `docs/adr/0001-separate-capa-from-capev2.md`, `docs/adr/0002-tag-as-evidence-over-hard-block.md`, `docs/adr/0003-passive-consumer-agent.md` — quyết định kiến trúc.
- `links.md` — nguồn tham khảo và taxonomy.
- `issues/issue_2026-09-18_review_intent_specs.md` — review intent/spec ban đầu.
- `issues/issue_2026-09-19_unresolved_spec_review.md` — gate R01–R08 và tiêu chí đóng.

## 1. Mục tiêu & phạm vi

Kế hoạch này đưa đề tài từ spec đã thẩm định sang prototype có kiểm chứng cho Phase 2. Điều kiện tiên quyết là Phase 0 tái kiểm tra R01–R08 và xác nhận issue 2026-09-19 đã được đóng trung thực trên tài liệu hiện hành. Phạm vi target là Windows PE theo spec §1.2 và các pipeline static/dynamic đã mô tả. Ranh giới: tài liệu này chỉ lập kế hoạch Phase 2; việc viết code chỉ khởi động sau khi Phase 0 pass.

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

### Module 1 — YARA Static + Telemetry Ingestion Adapter

- **Mục tiêu:** phát hiện promptware từ PE strings và telemetry CAPEv2 qua luật YARA + adapter API arguments.
- **Nguồn spec:** spec §3.2 (dòng 209–293).
- **Đầu vào → Đầu ra:** PE strings + CAPEv2 report → findings + `SANDBOX_API_LOG` records (enum §4.1).
- **Phụ thuộc:** Module 0; R04 vì cần fixture/phiên bản/report schema.
- **Tiêu chí hoàn thành:** rule biên dịch; adapter trích API args mục tiêu; chạy trên fixture R04 mà không cần thực thi mã độc sống.

### Module 2 — Meta Prompt Guard-86M service

- **Mục tiêu:** phân loại chuỗi nghi vấn bằng Meta Prompt Guard-86M và phát tín hiệu neural guardrail.
- **Nguồn spec:** spec §3.4 (dòng 304–309).
- **Đầu vào → Đầu ra:** chuỗi nghi vấn → nhãn + xác suất theo ngưỡng 0.75 (spec §3.4); trạng thái trung gian dưới ngưỡng chờ chốt tại T00.
- **Phụ thuộc:** Module 0.
- **Tiêu chí hoàn thành:** service phân loại được; đo latency thực trên CPU/GPU và gắn cấu hình đo R08.

### Module 3 — Mandiant CAPA parser (Allowlist Projection)

- **Mục tiêu:** tạo capability branch không đưa raw free-text từ CAPA/CAPE vào agent context.
- **Nguồn spec:** spec §3.3 (dòng 297–300).
- **Đầu vào → Đầu ra:** `capa -j` PE tĩnh và CAPE report → chỉ `tactic/technique_id/technique_name/namespace`, tước free-text.
- **Phụ thuộc:** độc lập với Module 0–2 trong Capability branch.
- **Tiêu chí hoàn thành:** projection loại bỏ raw strings và chú thích/log tự do, giữ capability có cấu trúc.

### Module 4 — Decision Policy Gate + Context Serialization

- **Mục tiêu:** hợp nhất detection branch và capability branch thành policy action, Spotlighting Chat payload, evidence JSON và final report JSON.
- **Nguồn spec:** spec §3.5 (dòng 313–363); spec §4 (dòng 378–619).
- **Đầu vào → Đầu ra:** findings + capabilities + processing/detection state → policy action + Spotlighting Chat payload + evidence/report JSON.
- **Phụ thuộc:** Module 0–3; R01/R07 vì vocabulary/schema phải thống nhất.
- **Tiêu chí hoàn thành:** 9 tổ hợp state cho hành động nhất quán với schema; report tham chiếu evidence tồn tại.

## 4. Phase 3 — Đánh giá & nghiệm thu

Phase 3 chạy protocol 4 nhóm của spec §6.1 sau khi đã bổ sung theo R06: paired samples, split chống leakage, baselines và định nghĩa attack success. Đo các chỉ số spec §6.3/§6.6–§6.7 như mục tiêu cần kiểm chứng: Detection Recall ≥90%, FPR ≤5%, ERR ≥95%, Latency overhead ≤15s, Schema compliance 100% với abstention đo riêng, De-obfuscation ≥90%. Baselines gồm no-guardrail, YARA-only, ML-only và full pipeline; cấu hình đo dùng workload/hardware/batch/concurrency/percentile theo R08. Các ngưỡng là target, không phải kết quả đã chứng minh.

## 5. Trình tự & phụ thuộc

Phase 0 chặn Phase 2. Trong Phase 2, Detection branch chạy Module 0 → Module 1 → Module 2; Capability branch chạy Module 3 song song vì không phụ thuộc detection branch. Hai branch hội tụ ở Module 4. Phase 3 chỉ bắt đầu sau khi Module 0–4 đạt tiêu chí hoàn thành.

## 6. Điều kiện nghiệm thu tổng thể

- [ ] Phase 0 §6 issue 2026-09-19 đóng sau tái kiểm tra.
- [ ] Module 0–4 đạt tiêu chí hoàn thành đã nêu.
- [ ] Phase 3 có báo cáo đủ chỉ số và baselines.
- [ ] `AGENTS.md` và tài liệu liên quan đồng bộ.
