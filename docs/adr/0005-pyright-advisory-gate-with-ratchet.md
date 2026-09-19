# Ghim pyright basic mode làm gate advisory có ratchet, không chặn cứng

## Bối cảnh & Quyết định
`pyrightconfig.json` (basic mode, `extraPaths: ["src"]`) được tạo ngày 2026-09-20 nhưng untracked và chưa gắn với quy trình nào. Baseline đo lần đầu (issue `issues/issue_2026-09-20_full_project_review_new_findings.md` §4): **276 errors + 2 warnings / 34 file** (~54 trong `src/guardrail/`, ~222 trong `tests/`), chủ yếu `reportArgumentType` (199) phát sinh từ TypedDict parse JSON và phép gán Optional; spot-check 3 điểm nóng không thấy bug runtime (`dataset_protocol.py:413` có guard `_is_number` chạy trước; `prompt_guard.py:461,464` là Protocol stub; `pipeline.py:439` là TypedDict do pipeline tự dựng).

Quyết định:
1. **Track `pyrightconfig.json`** trong git để baseline tái lập được từ fresh checkout.
2. pyright là **gate advisory (không chặn)** kèm **ratchet**: mọi thay đổi không được làm tăng tổng số diagnostics so với baseline đã ghi; số liệu baseline nằm trong issue trên §4 và được đo lại khi có tranh chấp.
3. Triage giảm dần theo nhóm rule, ưu tiên `reportTypedDictNotRequiredAccess` / `reportIndexIssue` (nhiều khả năng trùm lỗi runtime nhất), rồi `reportArgumentType`.

## Lý do & Đánh đổi
Basic mode trên code JSON-heavy với TypedDict `total=False` sinh nhiều cảnh báo Optional loại giả (pyright không hiểu TypeGuard tự viết như `_is_number`), nên chặn cứng ngay sẽ kéo theo mẹo hoá code (`assert`/`isinstance` thừa) mà chưa thấy lợi ích tương ứng; nhưng bỏ hẳn type-check là mất một lớp chống hồi quy miễn phí. Ratchet giữ chi phí biên thấp: cấm tăng, không ép sửa 276 lỗi cũ trong một wave. Đánh đổi đã chấp nhận: tổng số diagnostics là chỉ số thô — một refactor hợp lý có thể thêm ít lỗi mới trong khi xoá nhiều lỗi cũ hoặc ngược lại; khi cần điều chỉnh baseline phải ghi rõ lý do trong issue/build-report kèm commit, không chỉnh âm thầm.
