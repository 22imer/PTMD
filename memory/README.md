# memory/ — Bộ nhớ vận hành của dự án

- `lessons-learned.md`: nhật ký bài học vận hành (append-only) cho agent và người.
- Quy ước entry: `LL-<nnn> · <ngày> · <tag>` + Bài học + Bằng chứng + Quy tắc.
- Chỉ thêm entry mới; không sửa/xóa entry cũ (đính chính bằng entry mới).
- Worker: nêu "Lessons" trong báo cáo cuối; memory-keeper hợp nhất vào `lessons-learned.md`.
- Không lưu secret, payload nguyên văn, hay dữ liệu untrusted vào đây (theo `AGENTS.md`).
