# Lessons Learned — Guardrail Malware Agent

> Nhật ký bài học vận hành. Bổ sung khi có bài học mới; mỗi entry kèm ngày + bằng chứng. Không thay thế spec/ADR.

## LL-001 · 2026-09-19 · audit
**Bài học:** Kết quả audit từ agent chạy model cũ có thể trích dẫn nội dung đúng nhưng số dòng sai lệch (~-17 dòng).
**Bằng chứng:** T00Policy (đời đầu) ghi ma trận §3.5.1 ở "289–301" trong khi file thật ở 309–319; wave sau phải chạy lại toàn bộ.
**Quy tắc:** Mọi claim kèm file:line đọc lại tươi tại thời điểm báo cáo; supervisor đối chiếu tối thiểu một mẫu số dòng của mỗi báo cáo.

## LL-002 · 2026-09-19 · process
**Bài học:** Header/checkbox của issue không phản ánh trạng thái thật ("Resolved/Closed" nhưng checklist §6 là 0/9).
**Bằng chứng:** issues/issue_2026-09-19_unresolved_spec_review.md dòng 4 vs dòng 263–271 tại thời điểm audit.
**Quy tắc:** Gate chấm theo nội dung artifact, không theo tuyên bố; chỉ tick checklist khi có bằng chứng.

## LL-003 · 2026-09-19 · process (self-referential claim)
**Bài học:** Câu "xác nhận độc lập bằng tái kiểm tra T00 (xem reports/phase0-gate.json)" xuất hiện khi report vẫn ghi BLOCK — tuyên bố tự tham chiếu chưa có artifact chống lưng.
**Bằng chứng:** spec §7 (dòng 730) vs reports/phase0-gate.json v1 tại thời điểm GateKeeper3/4 kiểm.
**Quy tắc:** Chỉ viết câu "đã xác nhận/verified" SAU khi artifact tương ứng tồn tại và khớp; gặp claim trỏ artifact phải mở artifact kiểm.

## LL-004 · 2026-09-19 · docs (drift)
**Bài học:** Sửa một tài liệu làm trôi nhiều nơi: line-range (PLAN/implemention), version refs (v1.2.0/v1.3.0/v1.4.0), số layer (Lớp 2 vs Lớp 3), tag (`<quarantined_evidence>` vs `<untrusted_malware_telemetry>`), enum (`SANDBOX_API_TRACE` vs `SANDBOX_API_LOG`), ngưỡng (0.50 vs 0.75).
**Bằng chứng:** chuỗi re-audit RA1–RA4 + GateKeeper3 phát hiện lần lượt các lệch trên.
**Quy tắc:** Tham chiếu theo mục (§) thay vì số dòng khi có thể; sau mỗi đợt fix chạy sweep toàn repo; một nguồn chuẩn duy nhất cho mỗi vocabulary.

## LL-005 · 2026-09-19 · spec-code
**Bài học:** Code tham chiếu trong spec cũng là code: `NormalizationEngine.normalize` mất `transform_chain` khi đệ quy (`transforms = []` mỗi lời gọi + return đệ quy).
**Bằng chứng:** spec §3.1 (dòng ~154, 178–181 gốc); mutation test trong re-audit chứng minh test bắt được.
**Quy tắc:** Spec nhúng code ⇒ review theo trace logic + test/mutation trước khi tin; fix code mẫu kèm test chain tích lũy.

## LL-006 · 2026-09-19 · schema (khả biểu diễn)
**Bài học:** Spec bắt phát bản ghi Lớp 5 (dispatcher HARD_BLOCK, canary leak) nhưng `provenance.type` là enum đóng 3 giá trị ⇒ bản ghi không validate được ("yêu cầu phát X" mà chưa kiểm "X biểu diễn được").
**Bằng chứng:** GateKeeper3 RA1-3; fix bằng mở enum + ví dụ §4.3 + verifier GateKeeper4 xác nhận 12/12 required hợp lệ.
**Quy tắc:** Mọi loại bản ghi bắt buộc phát phải có ví dụ valid/invalid + validator chạy trước khi đóng gate; kiểm từng field required có miền giá trị hợp lệ.

## LL-007 · 2026-09-19 · env (agent/model)
**Bài học:** Agent type `reviewer` chạy model `openai-codex/gpt-6-astra` lỗi "not supported when using Codex with a ChatGPT account" — retry vô ích.
**Bằng chứng:** GateKeeper (đời đầu, failed exit 1) → thay bằng agent `task`, chạy tốt.
**Quy tắc:** Lỗi model/config ⇒ đổi agent type (fallback `task`) và ghi rõ thay thế trong báo cáo; không nhầm với lỗi nội dung.

## LL-008 · 2026-09-19 · env (đa agent một worktree)
**Bài học:** Nhiều agent chung một cây: checkout branch phá state agent khác; commit thường có thể trộn file staged của agent khác; pip cài song song dễ hỏng venv.
**Bằng chứng:** rủi ro thiết kế khi 5 agent soạn song song; quy ước đã áp dụng: `git commit --only <paths>` + retry index.lock, pip bọc `flock /tmp/ptmd-pip.lock`.
**Quy tắc:** Không checkout/switch branch khi còn agent khác; commit theo path; pip luôn qua flock; ghi CHỈ file thuộc phạm vi mình.

## LL-009 · 2026-09-19 · verify (mutation)
**Bài học:** "Test xanh" chưa chứng minh test bắt được lỗi thật.
**Bằng chứng:** ContractWatch seed 4 mutation trên bản sao /tmp (xoá HARD_BLOCK, thêm ALLOW, xoá INCONCLUSIVE, xoá required) — cả 4 đều làm test FAIL như mong đợi.
**Quy tắc:** Với contract/test quan trọng, supervisor chạy ≥1 mutation trên bản sao và chứng minh red-green trước khi kết luận PASS.

## LL-010 · 2026-09-19 · fixture/pin
**Bài học:** Fixture tổng hợp chứa sha256 của input rỗng + nhãn "Verified Test Fixture" — placeholder trông như thật; pin YARA/CAPEv2 ban đầu chỉ là "lời hứa T01".
**Bằng chứng:** RA3-2/RA3-3; fix: fixture_metadata synthetic + hash placeholder, nhãn hạ thành "đối chiếu tĩnh", reports/integration-pin.json chứa giá trị thật (YARA v4.5.8, CAPEv2 commit, HF revision — verifier đối chiếu 6/6).
**Quy tắc:** Fixture tổng hợp phải tự khai; pin phải fetch từ nguồn thật hoặc hạ nhãn xuống đúng mức bằng chứng.

## LL-011 · 2026-09-19 · grep/ngôn ngữ
**Bài học:** Sweep cụm cấm bắt cả câu phủ định hợp lệ và mô tả lịch sử (ví dụ "không triệt tiêu hoàn toàn", verdicts_v1).
**Bằng chứng:** final sweep: hits nằm ở links.md:48/162 (phủ định) và reports/phase0-gate.json (lịch sử).
**Quy tắc:** Khi sweep, phân loại từng hit (vi phạm / phủ định / lịch sử); không "sửa" câu phủ định.

## LL-012 · 2026-09-19 · process (chuỗi gate)
**Bài học:** Chuỗi hiệu quả cho gate: audit v1 (executor + supervisor độc lập) → fix có quyết định ghi log (D01–D18) → re-audit bằng agent MỚI → supervisor chốt điều kiện PASS → hoàn tất artifact (report v2 + issue ticks) trong cùng change-set.
**Bằng chứng:** T00 v2: 8/8 CLOSED, gate PASS; reports/phase0-gate.json v2.
**Quy tắc:** Không mở wave sau khi gate chưa PASS; mỗi mục có đúng 1 supervisor; quyết định thiết kế luôn ghi kèm artifact truy vết.
