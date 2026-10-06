# Laya làm consumer thụ động chỉ cho luồng đủ điều kiện

## Bối cảnh & Quyết định

Pipeline hiện phân tích tệp và báo cáo CAPE/CAPA không đáng tin cậy, đồng thời phát verdict theo policy Guardrail. Cần một nhánh advisory riêng để tổng hợp malware behavior mà không làm thay đổi contract report hoặc trao quyền cho model quyết định luồng xử lý.

Chọn Laya làm consumer tùy chọn, chỉ được gọi khi policy là `COMPLETE + NOT_DETECTED + ALLOW`, mọi detector coverage và facts coverage đều `COMPLETE`, và các đầu vào cùng mẫu được binding theo SHA-256. Không dùng `forward_to_agent`, `NOT_DETECTED` hoặc `ready_for_ai` như một verdict `BENIGN`. Laya nhận compact canonical state và câu hỏi đóng do workflow tin cậy cung cấp; raw text, IOC, endpoint, và free text từ CAPE/CAPA không vào model state.

Kết quả chi tiết được xuất trong companion `malware_analysis` độc lập, có provenance và trạng thái/abstention riêng. Legacy final report schema, ma trận policy, Tag-as-Evidence và bốn baseline benchmark không đổi. Observed network indicators ở sidecar riêng; DNS/HTTP observation không tự chứng minh C2. Capability chỉ biểu thị năng lực theo CAPA, không xác nhận thực thi. Canary verification áp dụng cho envelope gồm legacy report và companion.

Reference pin: `laya==0.3.28`; model `convaiinnovations/laya` revision `7b928d828b7b0e022f929d9bd2e44165aa270148`; expected `model.safetensors` SHA-256 `891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c`. Adapter lazy-load offline và xác minh revision/digest trước khi nạp. Workflow taxonomy và câu hỏi có hash. Confidence cutoff `0.80` chỉ là ngưỡng abstention tạm; calibration status luôn `UNCALIBRATED` cho tới khi có phép đo phù hợp. Lỗi package, cache, digest, inference, truncation không được che bằng fallback.

## Lý do & Đánh đổi

Cổng policy + coverage + same-sample binding tránh biến forwardability hoặc kết quả chưa phát hiện thành giả định dữ liệu sạch. Canonical state thu hẹp nội dung attacker-controlled được chuyển cho Laya; sidecar IOC giữ lại quan sát mạng và provenance mà không đưa URL/host vào câu hỏi model. Companion schema giữ kết quả không tương thích tách khỏi consumer report hiện hữu. Opt-in và lazy offline loading giữ nguyên hành vi mặc định, không tự tải model hay tạo kết nối mạng.

Đánh đổi là consumer abstain nhiều khi detector/facts coverage thiếu, metadata không binding, hoặc câu trả lời không thuộc vocabulary. Zero-shot family label có thể sai; confidence chưa được hiệu chỉnh và threshold chưa được xác nhận thực nghiệm. Vì vậy output chỉ hỗ trợ phân loại/điều tra, không thay analyst, policy verdict, bằng chứng IPI, bằng chứng C2, hay số liệu hiệu quả benchmark. Pin nguồn và checksum tái lập artifact nhưng không chứng minh model đã được tải, smoke-tested hoặc có chất lượng phù hợp.
