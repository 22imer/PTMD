# Phân định rõ ràng giữa Mandiant CAPA và CAPEv2 Sandbox

## Bối cảnh & Quyết định
Tài liệu sơ khởi từng dùng thuật ngữ nhập nhằng "CAPA Sandbox", gây nhầm lẫn giữa công cụ nhận diện khả năng hành vi và môi trường máy ảo thực thi mã độc. Chúng tôi quyết định tách biệt hoàn toàn thành hai bản thể độc lập: **CAPEv2 Sandbox** đảm nhiệm thực thi động và dump bộ nhớ RAM, còn **Mandiant CAPA** là công cụ trừu tượng hóa dữ liệu sang kỹ thuật MITRE ATT&CK và tước bỏ chuỗi văn bản tự do nguy hiểm.

## Lý do & Đánh đổi
Việc này loại bỏ hoàn toàn sự mơ hồ kỹ thuật trong kiến trúc, đảm bảo Mandiant CAPA đóng đúng vai trò là bộ khử trùng dữ liệu (Data Sanitizer) thay vì bị ngộ nhận là môi trường chạy mã độc.
