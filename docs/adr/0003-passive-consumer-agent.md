# Định vị Agent theo mô hình Thụ động (Passive Consumer) thay vì Điều khiển tương tác (Interactive Controller)

## Bối cảnh & Quyết định
Chúng tôi cân nhắc giữa việc trao quyền cho Agent trực tiếp điều khiển Sandbox (ra lệnh thực thi, hook API qua giao thức MCP) và việc cô lập Agent thành đối tượng nhận dữ liệu thụ động. Chúng tôi quyết định định vị Agent là **Passive Consumer**: toàn bộ quy trình chạy sandbox và trích xuất dữ liệu diễn ra độc lập; Agent chỉ nhận báo cáo đã qua rào chắn và không có quyền thực thi hệ thống hay kết nối mạng.

## Lý do & Đánh đổi
Quyết định này chặn đứng bề mặt lạm dụng công cụ trực tiếp (Excessive Agency / MITRE ATLAS AML.T0053 / OWASP LLM06) — kể cả khi suy luận bị thao túng, Agent không có công cụ phá hoại nào để thực thi; rủi ro tồn dư về thao túng suy luận vẫn được đo bằng `AS_tool` (spec §6.4). Đánh đổi là hệ thống mất đi khả năng tương tác linh hoạt thời gian thực giữa Agent và máy ảo Sandbox.
