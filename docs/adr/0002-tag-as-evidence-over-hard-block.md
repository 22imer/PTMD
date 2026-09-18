# Ưu tiên chính sách Tag-as-Evidence thay vì Hard Block khi phát hiện Promptware

## Bối cảnh & Quyết định
Khi lớp quét phát hiện câu lệnh prompt injection trong tệp tin hoặc bộ nhớ, có hai lựa chọn chính: hủy bỏ tiến trình phân tích (Hard Block) hoặc tiếp tục phân tích. Chúng tôi quyết định áp dụng chính sách **Tag-as-Evidence**: vô hiệu hóa khả năng thực thi của câu lệnh bằng cơ chế escaping và đóng gói trong thẻ phân tách dữ liệu thụ động (`<untrusted_malware_telemetry>`, spec §3.5.2), đồng thời gắn nhãn đây là bằng chứng tiêm nhiễm chỉ thị gián tiếp (MITRE ATLAS AML.T0051.001) để đưa vào báo cáo. ATT&CK T1497 (Virtualization/Sandbox Evasion) KHÔNG được gán mặc định cho mọi promptware; nó chỉ áp dụng khi mẫu thể hiện logic né tránh ảo hóa/sandbox một cách tường minh.

## Lý do & Đánh đổi
Trong nghiệp vụ an ninh mạng, câu lệnh tấn công AI chính là bằng chứng tố giác hành vi ác ý của tệp tin. Nếu ngắt phân tích (Hard Block), hệ thống sẽ bỏ lỡ toàn bộ thông tin tình báo đe dọa (Threat Intelligence) về mẫu mã độc đó. Thay vì cam kết loại bỏ hoàn toàn, hệ thống áp dụng phòng thủ theo chiều sâu (Defense-in-Depth) để giảm thiểu rủi ro tồn dư: escaping, prompt isolation và context ingress filtering nhiều tầng nhằm hạ thấp xác suất kích hoạt suy luận sai lệch của Agent, trong khi rủi ro tồn dư vẫn được ghi nhận thay vì phủ nhận.
