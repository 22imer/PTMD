# Malware Analysis Agent Guardrail

Hệ thống rào chắn bảo vệ mô hình ngôn ngữ lớn (LLM Agent) chuyên trách phân tích mã độc trước các kỹ thuật tấn công tiêm nhiễm chỉ thị gián tiếp (Indirect Prompt Injection).

## Core Concepts

**Malware Sample**:
Tệp tin nhị phân hoặc tài liệu nghi vấn được đưa vào pipeline để kiểm tra và phân tích an toàn.
_Avoid_: Virus, suspect file, test sample, infected target

**Promptware**:
Câu lệnh đối kháng được kẻ tấn công nhúng vào cấu trúc tệp tin hoặc bộ nhớ tiến trình nhằm thao túng suy luận của mô hình ngôn ngữ lớn.
_Avoid_: Malicious prompt, injection string, trick text, jailbreak script

**Indirect Prompt Injection (IPI)**:
Kỹ thuật tấn công mà câu lệnh thao túng được đưa vào ngữ cảnh của Agent thông qua kênh dữ liệu gián tiếp thay vì qua giao diện trò chuyện trực tiếp của người dùng.
_Avoid_: Direct injection, chat jailbreak, system prompt hack

## Analysis & Detection Components

**CAPEv2 Sandbox**:
Môi trường máy ảo độc lập và cô lập chuyên trách thực thi mã độc, bóc tách cấu hình, và tự động trích xuất bộ nhớ tiến trình.
_Avoid_: CAPA Sandbox, dynamic VM, execution container

**Mandiant CAPA**:
Công cụ dựa trên tập luật tĩnh và động để nhận diện khả năng hành vi của mã độc và ánh xạ trực tiếp sang kỹ thuật MITRE ATT&CK. Đầu ra của CAPA được chiếu theo allowlist capability, nhờ đó thu hẹp đáng kể bề mặt tấn công từ các chuỗi văn bản tự do (giảm thiểu, không loại bỏ hoàn toàn).
_Avoid_: CAPA Sandbox, behavior scanner, dynamic emulator

**YARA**:
Công cụ nhận diện mẫu dựa trên tập luật chuỗi và biểu thức chính quy, áp dụng cho cả tệp tin tĩnh trên đĩa, bộ nhớ tiến trình đang chạy, và báo cáo hành vi động.
_Avoid_: Antivirus scanner, signature matcher

**Meta Prompt Guard**:
Mô hình phân loại chuỗi chuyên biệt siêu nhẹ dựa trên kiến trúc DeBERTa-v2 nhằm phát hiện các nỗ lực tiêm nhiễm chỉ thị và vượt rào ở tầng ngữ nghĩa.
_Avoid_: LLM Judge, safety filter, content moderation model

## Policy & Governance

**Tag-as-Evidence**:
Chính sách an toàn vô hiệu hóa khả năng thực thi đang hoạt động của câu lệnh đối kháng và đóng gói nó thành quan sát pháp y thụ động kèm siêu dữ liệu cảnh báo, cho phép bảo toàn quy trình phân tích. Rủi ro tồn dư vẫn còn: mô hình ngôn ngữ có thể bị ảnh hưởng bởi ngữ nghĩa của dữ liệu đã đóng gói, nên escaping và prompt isolation chỉ giảm thiểu chứ không triệt tiêu nguy cơ.
_Avoid_: Hard block, drop sample, sanitize-only

**Passive Consumer Agent**:
Mô hình AI Agent chỉ tiếp nhận và lập luận trên dữ liệu đã qua quy trình làm sạch và trừu tượng hóa, hoàn toàn không sở hữu quyền tương tác trực tiếp với môi trường thực thi mã độc.
_Avoid_: Interactive Agent, Sandbox Controller, Autonomous Analyst

**Quarantined Evidence**:
Khối dữ liệu chứa câu lệnh đối kháng đã được mã hóa an toàn và đóng gói trong cấu trúc thẻ cách ly độc lập để phục vụ lập luận điều tra.
_Avoid_: Redacted text, raw payload, unescaped string

**Execution Rails**:
Cơ chế kiểm soát ranh giới thực thi tại cổng ra của Agent, ngăn chặn việc gọi các công cụ trái phép hoặc các thao tác vượt quá thẩm quyền đọc dữ liệu. Mọi dữ liệu do các công cụ truy vấn trả về đều phải qua bộ lọc context ingress; quyền read-only không đồng nghĩa nội dung trả về đáng tin cậy.
_Avoid_: Output filter, permission check, post-processing guard
