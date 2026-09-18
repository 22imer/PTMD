# [SUPERSEDED] Tiền xử lý phát hiện Prompt Injection cho Agent phân tích mã độc
> **GHI CHÚ:** Tài liệu này là ý tưởng sơ khởi và đã được thay thế chính thức bởi:
> - `intent/research_pre_validate.md` (Nghiên cứu kiến trúc)
> - `specs/guardrail_malware_agent_spec.md` (Bản đặc tả kỹ thuật chi tiết)

# Problem Statement
- Khi thực hiện phân tích mã độc chính agent phân tích mã độc có thể bị tấn công.
- Đưa ra luật phát hiện và mapping các dữ liệu đầu vào agent cho tiền xử lý các dạng tấn công thuộc MITRE ATLAS và OWASP LLM TOP 10
- Sử dụng YARA để làm công cụ phân tích tĩnh
- Dùng CAPEv2 Sandbox để chạy mã độc trong môi trường an toàn; Mandiant CAPA và YARA để bóc tách hành vi và kiểm tra các cuộc tấn công nhắm vào Agent.
- Tuân thủ MITRE ATLAS và OWASP LLM TOP 10
# Proposed Outcome
- Một công cụ có sử dụng học máy ML để phát hiện các cuộc tấn công trên
- Đưa ra được evidence của cuộc tấn công và mapping tương ứng theo tiêu chuẩn
- Chạy công cụ trên 1 file mã độc, thấy 'Dấu vết Prompt Injection' -> Có sử dụng kỹ thuật prompt injection bảo agent bỏ qua hoặc không xử lý đoạn đó
- Khi phát hiện không có dấu vết nào (với điều kiện các bước quét đạt trạng thái hoàn tất COMPLETE) sẽ duyệt cho Agent tiếp tục phân tích các năng lực đã được làm sạch, dữ liệu vẫn được gắn cờ không tin cậy (untrusted).
# Affected Users & System
- Agent: Không được chạy workflow phân tích trước khi xử lý
- Hệ thống: Xử lý và chạy các bộ luật YARA đảm bảo an toàn

# Constraint & Out of Scope
- Chỉ tìm kiếm và gợi ý các công cụ sử dụng
- Chưa thực hiện xây dựng hệ thống trong pha nghiên cứu

# Out of Scope
- Không tự động sửa các file tìm kiếm đã tạo
- Không đăng nhập, không tải media, không crawl toàn bộ trang web.
- Không chạy mã độc hại 
- Không viết code trong đợt này

# Open Question
- Đã có hệ thống nào đã được triển khai và áp dụng trong thực tế chưa
- Tìm kiếm được nghiên cứu nào về chủ đề này
- Tên chủ đề có thực sự chính xác với yêu cầu
- Hệ thống dạng guardrail được các công ty hàng đầu tạo kiểu gì