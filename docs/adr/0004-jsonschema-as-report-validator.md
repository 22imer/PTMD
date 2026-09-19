# Ghim `jsonschema` làm validator báo cáo thay vì đưa Guardrails AI vào prototype

## Bối cảnh & Quyết định
Spec §3.6 nêu Guardrails AI cho việc validate output Lớp 5, nhưng prototype Phase 2 không thêm
dependency đó. Validator được ghim là **`jsonschema==4.26.0`** (manifest: `reports/environment.json`),
chạy trực tiếp trên `schemas/final_report.schema.json` Draft-07 đã chốt ở T00 — chính là contract
mà Guardrails AI sẽ bọc lại sau. Cổng kiểm output gồm **ba lớp độc lập** trong `src/guardrail/report.py`,
không lớp nào thay thế lớp khác:

1. **Structural** — JSON Schema Draft-07 (§4.2) qua `jsonschema`; schema là source of truth.
2. **Reference** — mọi `evidence_id` trong report phải tồn tại trong kho evidence **cùng artifact**;
   tham chiếu treo là lỗi validation, không phải cảnh báo.
3. **Verdict/abstention consistency** — cột "Ràng buộc Verdict" của ma trận §3.5.1 áp qua
   `banned_verdicts`; `report_status=ABSTAINED_PARTIAL` buộc `verdict=INCONCLUSIVE`,
   `threat_score`/`confidence` là `null` và có `abstention_metadata`. Hết ngân sách re-ask (≤2 lần)
   thì fallback abstention, không bao giờ ép `BENIGN`.

**Điều kiện swap sang Guardrails AI:** chỉ khi (a) contract §4.2 giữ nguyên hoặc có bản schema mới
được ghim cùng kỳ, (b) Guardrails AI tái lập được đủ ba lớp trên trong test, và (c) môi trường
triển khai thật cần tới các tính năng ngoài structural validation (guard/hub, tích hợp runtime).
Khi đó `jsonschema` vẫn là validator nền để so chéo, không bị gỡ bỏ.

## Lý do & Đánh đổi
Prototype ưu tiên contract ổn định, tất định và offline: `jsonschema` là thư viện chuẩn, nhẹ, đã
được ghim phiên bản và có test mutation chứng minh bắt drift schema; thêm Guardrails AI lúc này
kéo theo dependency nặng (framework guard, tích hợp LLM) mà chưa có nhu cầu tương ứng, đồng thời
làm mờ ranh giới "schema §4.2 là contract". Đánh đổi: tài liệu spec §3.6 vẫn nhắc Guardrails AI,
nên quyết định hoãn này phải được ghi lại (ADR này + `reports/build-report.md`) để không bị hiểu là
đã triển khai Guardrails AI; hai lớp reference/abstention là phần bổ sung ngoài phạm vi structural
validation và sẽ phải được ánh xạ lại khi swap.
