# Nghiên cứu kiến trúc Guardrail đa tầng phòng chống Indirect Prompt Injection cho Agent phân tích mã độc
**Document Identifier:** INTENT-RES-AI-2026-01  
**Version:** 1.2.1 (Active Research Intent)  
**Status:** Approved Baseline — Paired with Spec v1.4.0 (đồng bộ diagram 2026-09-19)  
**Related Documents:**
- **Domain Glossary:** `CONTEXT.md` (Ubiquitous Language)
- **Architectural Decisions:** `docs/adr/0001-separate-capa-from-capev2.md`, `0002-tag-as-evidence-over-hard-block.md`, `0003-passive-consumer-agent.md`
- **Technical Specification:** `specs/guardrail_malware_agent_spec.md` (Version 1.4.0)
- **Research Links & Evidence:** `links.md`
- **Audit & Issue History:** `issues/issue_2026-09-18_review_intent_specs.md` (Status: Resolved / Closed)

---

## 1. Problem Statement & Giả thuyết nghiên cứu

### 1.1 Bối cảnh bài toán
Trong các hệ thống phân tích mã độc và điều hành an ninh mạng (AI-SOC) hiện đại, AI Agent (Large Language Models) ngày càng được sử dụng để tóm tắt hành vi mã độc, phân tích disassembly, và đưa ra khuyến nghị xử lý. Tuy nhiên, chính Agent phân tích lại trở thành bề mặt tấn công mới:

- **Tấn công tĩnh (Static Indirect Prompt Injection)**: Kẻ tấn công nhúng các câu lệnh đối kháng (Promptware) vào các chuỗi ký tự (strings), section headers, metadata, PE resources, hoặc file đính kèm.
- **Tấn công động (Runtime / In-Memory Promptware)**: Đối với mã độc được đóng gói (packed) hoặc mã hóa (XOR/RC4/AES), chuỗi tấn công không lộ diện trên đĩa mà chỉ được giải mã (unpack) vào bộ nhớ RAM khi chạy trong Sandbox, hoặc được cố tình đẩy vào các bản ghi log thông qua các API calls (ví dụ: `OutputDebugString`, HTTP User-Agent, Window titles).
- **Kỹ thuật lẩn tránh & Mã hóa (Obfuscation & Evasion)**: Kẻ tấn công sử dụng Base64, Hex, Leetspeak, Homoglyphs (ký tự Unicode tương tự), Zero-Width characters hoặc phân mảnh câu lệnh để qua mặt các bộ lọc regex/từ khóa đơn giản.
- **Nguy cơ chiếm quyền (Agent Hijacking & Evasion)**: Khi Agent đọc các file thô hoặc bản ghi log từ Sandbox, câu lệnh injection sẽ lừa Agent:
  1. Thay đổi kết luận phân tích: Đánh giá file mã độc nguy hiểm thành phần mềm lành tính (`Benign`) hoặc bỏ qua các hành vi nguy hiểm.
  2. Lạm dụng quyền hạn công cụ (Tool Misuse): Lừa Agent thực thi các tool nhạy cảm ngoài ý muốn (chạy lệnh shell, xóa log, hoặc gửi dữ liệu ra ngoài).
- **Thách thức Dương tính giả (False Positive Dilemma)**: Mẫu mã độc thông thường luôn chứa các chuỗi lệnh hệ thống (`cmd.exe /c powershell -enc`, `bypass`, `admin`, `eval()`). Hệ thống Guardrail phải phân biệt chính xác giữa *Chuỗi hành vi mã độc thông thường* và *Chuỗi câu lệnh thao túng Agent*.

### 1.2 Giả thuyết nghiên cứu trọng tâm (Core Research Hypothesis)
> **Câu hỏi nghiên cứu trung tâm:**  
> *"Một kiến trúc Guardrail đa tầng kết hợp biểu tượng (YARA/CAPA) và mô hình học máy ngữ nghĩa (Meta Prompt Guard-86M) có thể giảm tỷ lệ tấn công thành công của Indirect Prompt Injection trên tệp Windows PE xuống bao nhiêu phần trăm, với chi phí độ trễ tính toán và mức độ suy giảm chất lượng phân tích mã độc nền là bao nhiêu?"*

### 1.3 Bảng đối chiếu thay đổi phạm vi (Scope Reconciliation Table)

| Thành phần / Yêu cầu | Intent sơ khởi (`pre-validate.md`) | Bản nghiên cứu hiện tại (`research_pre_validate.md`) | Trạng thái & Lý do kỹ thuật |
| :--- | :--- | :--- | :--- |
| **Đối tượng bảo vệ** | Agent phân tích mã độc | Agent phân tích mã độc (Passive Consumer) | **Giữ lại** — Giữ đúng trọng tâm an toàn cho Agent. |
| **Phạm vi rào chắn** | Tiền xử lý tĩnh (Static Pre-processing) | Đa tầng: Lớp 0 (De-obfuscation), Tĩnh, Động trong RAM, Ngữ nghĩa, Thực thi | **Mở rộng** — Cần thiết vì packer giấu promptware trong RAM, lọc tĩnh là không đủ. |
| **Định dạng mục tiêu** | Mọi loại mã độc nói chung | Chuyên sâu Windows PE (`.exe`, `.dll`) | **Thu hẹp / Tập trung** — Đảm bảo tính khả thi sâu của CAPEv2, PE-sieve, CAPA. |
| **Công cụ động** | "CAPA Sandbox" (thuật ngữ chưa chuẩn) | CAPEv2 Sandbox (máy ảo) + Mandiant CAPA (trừu tượng hóa) | **Làm rõ bản thể** — Phân định rõ Sandbox thực thi và Tool nhận diện capability. |
| **Chính sách xử lý** | Dừng hoặc cho phép | Ma trận 3 chiều (`Tag-as-Evidence`, `Sanitize`, `Block`) | **Mở rộng** — Bảo tồn bằng chứng tình báo mã độc cho chuyên viên SOC. |

---

## 2. Threat Model (Mô hình đe dọa)

- **Tác nhân đe dọa (Attacker)**: Tác giả mã độc hoặc kẻ tấn công có hiểu biết về quy trình phân tích tự động bằng AI.
- **Bề mặt tấn công (Attack Surface)**:
  - Chuỗi tĩnh trong binary (PE headers, sections, resources, metadata).
  - Vùng nhớ tiến trình sau khi mã độc tự giải nén trong Sandbox (In-Memory Unpacked Payload).
  - Báo cáo hành vi động của Sandbox (API traces, Network logs, Registry writes, Debug strings).
- **Vector tấn công cốt lõi**:
  - **Indirect Prompt Injection (IPI) / Promptware**: Chỉ thị giả mạo quyền hệ thống ép Agent bỏ qua phân tích (`AML.T0051.001`).
  - **Instruction vs. Data Confusion**: Khai thác việc LLM không tự phân biệt được đâu là dữ liệu cần đọc và đâu là câu lệnh cần thi hành.
  - **Excessive Agency Exploitation**: Khai thác quyền gọi tool của Agent để gây hại (`AML.T0053`).
  - **Obfuscated / Multi-encoding Payloads**: Nhúng payload dưới dạng Base64, Hex, Leet-speak, hoặc Unicode nhằm vượt qua lớp lọc chuỗi đơn thuần (`AML.T0043`).

---

## 3. Proposed Outcome (Kết quả kỳ vọng)

1. **Báo cáo nghiên cứu công nghệ**:
   - Khảo sát các công cụ guardrail mã nguồn mở và kỹ thuật hiện đại: **Vigil-LLM**, **CAPEv2 Sandbox**, **PE-sieve**, **Mandiant CAPA**, **Meta Prompt Guard-86M**, **NVIDIA NeMo Guardrails**, và **Microsoft Spotlighting**.
2. **Đề xuất kiến trúc Guardrail đa tầng (Static & Dynamic Architecture)**:
   - Tách biệt hai luồng: Nhánh Phát hiện (Detection) và Nhánh Năng lực (Capability).
   - Tích hợp lớp **Normalization & De-obfuscation Engine** (giải mã Base64, Hex, chuẩn hóa Unicode/Zero-width).
3. **Đề xuất thiết kế tập luật & Cơ chế phát hiện (Detection Rules Design)**:
   - Bộ mẫu luật **YARA tĩnh** phát hiện mẫu câu injection phổ biến (tham chiếu Vigil-LLM).
   - **Telemetry Ingestion Adapter** trích xuất tham số API debug (`OutputDebugString`, `SetWindowText`) từ CAPEv2 report đưa vào pipeline quét text.
   - Cơ chế quét bộ nhớ tiến trình (`yara <rules> <PID>` hoặc `.dmp`).
4. **Ma trận chính sách xử lý khi phát hiện tấn công (Decision Policy Matrix)**:
   - Áp dụng nguyên tắc: **Không phát hiện (NOT_DETECTED) không đồng nghĩa an toàn**; chỉ được coi là Clean khi trạng thái xử lý đạt `COMPLETE`. Nếu dữ liệu bị cắt ngắn (`PARTIAL`), phải gắn nhãn `INCONCLUSIVE`.
   - Phân định 3 hành động: `Tag-as-Evidence` (bảo tồn phân tích), `Sanitize / Drop`, và `Pipeline Abstention` (khi sandbox sập).
5. **Bảng khung Mapping tiêu chuẩn an toàn & Schemas**:
   - Ánh xạ chi tiết theo **MITRE ATLAS (Snapshot 2026.09)** và **OWASP LLM Top 10 (2025)**.
   - Đặc tả chuẩn cấu trúc JSON Draft-07 cho `QuarantinedAdversarialEvidence` và `MalwareAgentFinalReport`.

---

## 4. Proposed Architecture (Kiến trúc đề xuất)

Hệ thống kết hợp phương pháp **Biểu tượng (Deterministic/Symbolic)** và **Học máy (Probabilistic/Neural)** qua hai nhánh dữ liệu song song độc lập, giữ nguyên mẫu PE gốc là bất biến (`immutable`):

```
                           [MẪU NHỊ PHÂN PE GỐC (BẤT BIẾN)]
                                          │
       ┌──────────────────────────────────┴──────────────────────────────────┐
       ▼ (Pha Tĩnh)                                                          ▼ (Pha Động)
┌──────────────────────────────────────┐            ┌──────────────────────────────────────────────┐
│ TRÍCH XUẤT TĨNH (STATIC EXTRACTION)  │            │ SANDBOX THỰC THI ĐỘNG (CAPEv2 SANDBOX)       │
│ - Trích xuất chuỗi có lọc (len >= 6) │            │ - Thực thi trong máy ảo Windows cô lập       │
│ - Giữ nguyên byte offset gốc         │            │ - PE-sieve quét RAM & dump unpacked PE       │
│                                      │            │ - Trích xuất Memory Dumps & Dynamic API Trace│
└──────────────────┬───────────────────┘            └──────────────────────┬───────────────────────┘
                   │                                                       │
                   ├───────────────────────────────────────────────────────┤
                   │                                                       │
                   ▼ (Nhánh 1: Detection Branch)                           ▼ (Nhánh 2: Capability Branch)
┌──────────────────────────────────────────────────────┐    ┌──────────────────────────────────────────────┐
│ LỚP 0: NORMALIZATION & DE-OBFUSCATION ENGINE         │    │ MANDIANT CAPA ABSTRACTION (TĨNH & ĐỘNG)      │
│ - Chuẩn hóa Unicode NFKD, xóa Zero-Width Characters  │    │ - Chạy `capa` trên PE tĩnh và CAPE report    │
│ - Ánh xạ ký tự đồng hình (Confusables Mapping)       │    │ - Chiếu (project) hành vi theo Allowlist     │
│ - Bounded Recursive Decoding (Base64, Hex - Depth 2) │    │   các kỹ thuật MITRE ATT&CK chuẩn            │
│   (Thực hiện trên bản sao text, giữ liên kết offset) │    │ - Tước bỏ toàn bộ raw text và mã máy tự do   │
└──────────────────────────┬───────────────────────────┘    └──────────────────────┬───────────────────────┘
                           │                                                       │
                           ▼                                                       │
┌──────────────────────────────────────────────────────┐                           │
│ LỚP 1: HEURISTIC & SIGNATURE SCANNERS                │                           │
│ - YARA Static Rules: Quét chuỗi bypass & canary      │                           │
│ - YARA Memory Scan: Quét memory dumps từ PE-sieve    │                           │
│ - Telemetry Ingestion Adapter (trích xuất, trước L0) + YARA Cuckoo Module   │                           │
└──────────────────────────┬───────────────────────────┘                           │
                           │                                                       │
                           ▼                                                       │
┌──────────────────────────────────────────────────────┐                           │
│ LỚP 3: SEMANTIC ML GUARDRAIL                         │                           │
│ - Meta Prompt Guard-86M quét chuỗi nghi vấn          │                           │
│ - Phân tách Malware Commands vs. Promptware          │                           │
└──────────────────────────┬───────────────────────────┘                           │
                           │                                                       │
                           ▼ [Adversarial Findings]                                ▼ [Capabilities JSON]
┌──────────────────────────────────────────────────────────────────────────────────┴───────────────────────┐
│ LỚP 4: DECISION POLICY GATE & CONTEXT SERIALIZATION                                                      │
│ - Đánh giá ma trận 3 chiều: Trạng thái Xử lý (Processing), Phát hiện (Detection), Hành động (Action)     │
│ - Tag-as-Evidence: Đóng gói chuỗi độc hại thành đối tượng thụ động, gắn nhãn AML.T0051.001               │
│ - Microsoft Spotlighting: Phân tách Kênh Chỉ thị (Message Role: System) và Kênh Dữ liệu (XML Delimiters)│
│ - Residual Risk Isolation: Dữ liệu raw chỉ lưu ở kho điều tra, không đưa nguyên văn payload vào Context  │
└──────────────────────────────────────────────────┬───────────────────────────────────────────────────────┘
                                                   │ Payload Context đã qua quản trị an toàn (vẫn mang cờ untrusted)
                                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ LỚP 5: RUNTIME EXECUTION RAILS & OUTPUT GOVERNANCE                                                       │
│ - Hardcoded Read-Only Dispatcher: Agent chỉ có quyền gọi các hàm truy vấn dữ liệu đã làm sạch            │
│ - Ingress Filtering: Mọi dữ liệu do tool trả về qua bộ lọc context ingress trước khi nạp Agent context  │
│ - Cấm tuyệt đối công cụ Shell, Thực thi tệp, hoặc Kết nối mạng ra ngoài                                  │
│ - Guardrails AI Schema Validation: Kiểm thực cấu trúc JSON Schema báo cáo đầu ra (cơ chế Re-ask/Abstain)│
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Scope & Constraints (Phạm vi & Ràng buộc)

### Constraints (Ràng buộc pha nghiên cứu)
- **Nghiên cứu & Thiết kế kiến trúc**: Trọng tâm là lý thuyết, khảo sát giải pháp, thiết kế luồng dữ liệu và threat modeling.
- **Không viết code sản phẩm hoàn chỉnh**: Chưa triển khai code production trong pha này.
- **Không chạy mã độc hại trực tiếp ngoài host**: Không thực thi mã độc hại ngoài môi trường kiểm soát; việc phân tích động chỉ khảo sát ở mức mô hình tích hợp Sandbox (CAPEv2).
- **Chất lượng nguồn tham khảo**: Ưu tiên tài liệu chính thức, paper học thuật (arXiv, IEEE), tài liệu kỹ thuật từ các tổ chức bảo mật uy tín (NIST, CSA, OWASP, MITRE).

### Out of Scope (Ngoài phạm vi)
- Huấn luyện (training) lại foundation model từ đầu.
- Xây dựng hệ thống tự động sửa chữa/vá file mã độc (Automatic Remediation).
- Tích hợp production thực tế vào hệ thống SIEM/SOC doanh nghiệp.

---

## 6. Research Questions (Câu hỏi nghiên cứu)

1. **Hiệu quả của YARA & De-obfuscation**: YARA tĩnh và Telemetry Ingestion Adapter kết hợp với bộ giải mã (Base64/Hex/Unicode) có thể bắt được những dạng Prompt Injection nào và có giới hạn ra sao?
2. **Kiểm soát Dương tính giả (False Positive Rate)**: Làm thế nào để phân biệt giữa các chuỗi lệnh khai thác mã độc thông thường (`cmd.exe`, `powershell`, `bypass`) với các câu lệnh tấn công nhắm vào Agent?
3. **Hiệu quả giảm thiểu bề mặt tấn công của CAPA**: Việc dùng Mandiant CAPA chuyển đổi từ raw assembly/dynamic logs sang structured JSON giúp giảm thiểu bao nhiêu phần trăm bề mặt tấn công của Prompt Injection?
4. **Hiệu quả của Chính sách Tag-as-Evidence**: Trong các kịch bản thực tế của SOC, giải pháp `Tag-as-Evidence` giúp bảo toàn bao nhiêu thông tin tình báo mối đe dọa so với việc `Hard Block` mẫu mã độc?
5. **Rủi ro tồn dư & Action Governance**: Làm thế nào để đảm bảo ngay cả khi Agent bị thao túng suy luận (do rủi ro tồn dư của Prompt Injection), hệ thống Execution Rails vẫn ngăn chặn được việc gọi tool phá hoại?

---

## 7. Acceptance Criteria (Tiêu chí nghiệm thu pha nghiên cứu)

- [ ] Khảo sát ít nhất **4 công cụ/framework bảo mật cốt lõi**: Vigil-LLM, CAPEv2/PE-sieve, Mandiant CAPA, Meta Prompt Guard/NeMo Guardrails.
- [ ] Tham chiếu ít nhất **5 nghiên cứu học thuật/báo cáo kỹ thuật uy tín**:
  - Paper gốc về Indirect Prompt Injection (Greshake et al.).
  - Báo cáo toán học của NIST về Guardrail Incompleteness (Vassilev Proof, 2026).
  - Nghiên cứu AI-SOC Neurosymbolic (arXiv:2609.10707, 2026).
  - Tiêu chuẩn OWASP LLM Top 10 (2025) và CSA MAESTRO Framework.
  - Tài liệu kỹ thuật YARA Cuckoo module và PE-sieve.
- [ ] Hoàn thành **Đặc tả cơ chế Normalization & De-obfuscation**: Quy định rõ quy trình giải mã Base64, Hex, và chuẩn hóa Unicode trước khi quét.
- [ ] Hoàn thành **Quy định Decision Policy Matrix**: Phân định rõ 3 chiều trạng thái (`Processing State`, `Detection State`, `Action Policy`).
- [ ] Hoàn thành **Bảng Mapping Ma trận tấn công** đối chiếu chuẩn xác theo **MITRE ATLAS Snapshot 2026.09** (`AML.T0051.001`, `AML.T0053`, `AML.T0054`, `AML.T0043`, `AML.T0015`, `AML.T0056`).
- [ ] Thiết kế **Giao thức đánh giá 4 nhóm mẫu (Four-Group Evaluation Dataset)** với 2 Ground Truth độc lập (`GT_Injection` vs `GT_Malware_Behavior`).
- [ ] Hoàn thiện tài liệu tổng hợp liên kết nghiên cứu (`links.md`) với trích dẫn URL và tóm tắt kỹ thuật đầy đủ.
- [ ] Đồng bộ nhất quán với **Bản đặc tả kỹ thuật** (`specs/guardrail_malware_agent_spec.md` v1.4.0), **Từ điển nghiệp vụ** (`CONTEXT.md`) và **Bộ 3 bản ghi quyết định kiến trúc** (`docs/adr/0001`, `0002`, `0003`).
