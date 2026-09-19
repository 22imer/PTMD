# Tổng hợp nguồn tài nguyên, nghiên cứu & công cụ Guardrail cho Agent phân tích mã độc

Tài liệu này hệ thống hóa toàn diện các công cụ, paper học thuật, giải pháp công nghiệp và kiến trúc bảo vệ **AI Agent** trong cả hai pha: **Phân tích tĩnh (Static Analysis)** và **Phân tích động (Dynamic / Runtime Analysis)** trước các nguy cơ **Indirect Prompt Injection (IPI)** và **Promptware**.

---

## 1. Lớp Runtime & Phân tích động (Dynamic Analysis & In-Memory Guardrails)

Kẻ tấn công thường che giấu câu lệnh Prompt Injection bằng Packer (Themida, VMProtect, UPX) hoặc mã hóa (XOR, RC4, AES). Khi nằm trên đĩa, các chuỗi này không lộ diện. **Chỉ khi mã độc được thực thi trong Sandbox, payload mới được giải mã vào bộ nhớ (RAM) hoặc đẩy vào logs.** Dưới đây là các công cụ và cơ chế để phân tích động và bắt prompt injection ở tầng runtime:

### 1.1 YARA Cuckoo Module & Quét bộ nhớ tiến trình (Process Memory Scanning)
- **Tài liệu chính thức YARA Cuckoo**: [https://yara.readthedocs.io/en/stable/modules/cuckoo.html](https://yara.readthedocs.io/en/stable/modules/cuckoo.html)
- **Tài liệu YARA Command Line**: [https://yara.readthedocs.io/en/stable/commandline.html](https://yara.readthedocs.io/en/stable/commandline.html)
- **Mô tả kỹ thuật**:
  - **Module `cuckoo` tích hợp trong YARA**: YARA hỗ trợ cú pháp `import "cuckoo"` cho phép viết các rule kiểm tra trực tiếp trên file báo cáo động JSON từ Sandbox (`yara -x cuckoo=behavior_report.json rules.yar target_file`; lưu ý `-x` ≡ `--module-data=MODULE=FILE` — kênh module-data, còn external variable là `-d`, xem errata SP-01 issue 2026-09-20). Rule có thể kiểm tra:
    - `cuckoo.network.http_user_agent(/regexp/)`, `cuckoo.network.http_request(/regexp/)` (bắt promptware giấu trong User-Agent hoặc URL request).
    - `cuckoo.registry.key_access(/regexp/)`, `cuckoo.filesystem.file_access(/regexp/)`, `cuckoo.sync.mutex(/regexp/)`.
  - **Quét trực tiếp RAM (`yara [OPTIONS] RULES_FILE <PID>`)**: YARA có khả năng quét trực tiếp vào không gian địa chỉ bộ nhớ của một tiến trình đang chạy (qua Process ID) hoặc quét file Memory Dump (`.dmp`).
- **Ý nghĩa cho đề tài**: Cực kỳ quan trọng. Cho phép dùng YARA không chỉ cho file tĩnh, mà còn để **quét bộ nhớ tiến trình sau khi mã độc tự unpack** và **quét trực tiếp báo cáo hành vi động của Sandbox** nhằm phát hiện chuỗi tấn công Agent.

---

### 1.2 CAPEv2 Sandbox (Config And Payload Extraction)
- **Kho mã nguồn**: [https://github.com/kevoreilly/CAPEv2](https://github.com/kevoreilly/CAPEv2)
- **Mô tả kỹ thuật**:
  - Sandbox phân tích động mã nguồn mở hàng đầu, phát triển từ nền tảng Cuckoo Sandbox.
  - Tự động hóa việc unpack mã độc, bypass các kỹ thuật anti-analysis / anti-VM / sleep delay, trích xuất cấu hình (configuration extraction) và tự động dump các vùng nhớ chứa payload đã được giải mã.
  - Xuất báo cáo hành vi động toàn diện dưới dạng file JSON cấu trúc (`behavior_report.json`), ghi nhận chi tiết API calls, network traffic, và memory dumps.
- **Ý nghĩa cho đề tài**: Cung cấp môi trường Sandbox an toàn để kích hoạt mã độc. Dữ liệu đầu ra của CAPEv2 (memory dump và JSON report) sẽ là đầu vào cho lớp Dynamic Guardrail trước khi chuyển tiếp cho Agent.

---

### 1.3 PE-sieve (`hasherezade/pe-sieve`)
- **Kho mã nguồn**: [https://github.com/hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve)
- **Mô tả kỹ thuật**:
  - Công cụ chẩn đoán bộ nhớ Windows, quét tiến trình đang chạy để phát hiện và dump các payload độc hại: Process Hollowing, Process Doppelgänging, Dynamic DLL Injection, Inline Hooks, và Shellcodes trong RAM.
  - Tự động tái tạo (reconstruct) và dump module mã độc đã unpack ra đĩa dưới dạng file PE hợp lệ.
- **Ý nghĩa cho đề tài**: Bóc tách lớp vỏ bọc (unpack) của mã độc trong RAM. Sau khi PE-sieve dump được file PE đã giải mã, hệ thống có thể đưa file này qua bộ quét YARA / Static Guardrail để kiểm tra xem bên trong ruột mã độc có giấu Prompt Injection hay không.

---

### 1.4 Mandiant CAPA Dynamic (Phân tích Capability từ Sandbox Report)
- **Kho mã nguồn**: [https://github.com/mandiant/capa](https://github.com/mandiant/capa)
- **Cơ chế Dynamic CAPA**: `capa <cape_report.json>`
- **Mô tả kỹ thuật**:
  - CAPA hỗ trợ phân tích trực tiếp trên báo cáo phân tích động của **CAPEv2**, **DRAKVUF**, hoặc **VMRay**.
  - Nhận diện các capability runtime (ví dụ: `inject code into another process`, `persist via Windows service`) và map sang **MITRE ATT&CK**.
- **Ý nghĩa cho đề tài (Data Sanitizer)**: Thay vì chuyển tiếp toàn bộ hàng chục nghìn dòng log thô của Sandbox (nơi kẻ tấn công có thể nhúng các chuỗi lừa đảo vào log API), CAPA đóng vai trò **Bộ lọc làm sạch dữ liệu**: Nó chiếu theo allowlist các kỹ thuật ATT&CK có cấu trúc, qua đó tước bỏ phần lớn các chuỗi văn bản tự do chưa kiểm duyệt (giảm thiểu bề mặt tấn công, không triệt tiêu hoàn toàn).

---

### 1.5 NexusCore MCP (AI-driven Dynamic Malware Analysis)
- **Kho lưu trữ / Thông tin**: [https://explore.market.dev/ecosystems/mcp/projects/nexuscore_mcp](https://explore.market.dev/ecosystems/mcp/projects/nexuscore_mcp)
- **Mô tả kỹ thuật**:
  - Dự án máy chủ MCP kết nối các LLM Agent với các công cụ dịch ngược và phân tích động cấp thấp: **Frida** (Dynamic Binary Instrumentation), **PE-sieve**, **Unicorn Engine**, **CAPEv2**, **CAPA** và **YARA**.
  - Cho phép Agent tương tác trực tiếp với tiến trình mã độc đang chạy trong môi trường kiểm soát.
  - Tích hợp cơ chế bảo vệ kép (dual scoring) và điều phối công cụ để chống **Tool Poisoning** và **Prompt-driven Evasion** (mã độc cố tình thao túng Agent qua kết quả trả về của tool).
- **Ý nghĩa cho đề tài**: Tài liệu tham khảo thực tế về cách một hệ thống Agent tương tác an toàn với các công cụ phân tích động cấp thấp mà không bị thao túng.

---

## 2. Công cụ & Framework Guardrail mã nguồn mở (Open-Source Defense Tools)

### 2.1 Vigil-LLM (`deadbits/vigil-llm`)
- **Kho mã nguồn**: [https://github.com/deadbits/vigil-llm](https://github.com/deadbits/vigil-llm)
- **Tài liệu YARA Scanner**: [https://vigil.deadbits.ai/overview/use-vigil/scanners/yara-heuristics](https://vigil.deadbits.ai/overview/use-vigil/scanners/yara-heuristics)
- **Mô tả kỹ thuật**:
  - Security scanner mã nguồn mở cho LLM prompts và responses, cung cấp cả Python SDK và REST API.
  - Sử dụng kiến trúc module đa tầng:
    - **YARA / Heuristics Scanner**: Quét chuỗi tĩnh bằng YARA v4.3.2 nhằm phát hiện các dấu hiệu *Instruction Bypass* (ví dụ: `ignore previous instructions`, `disregard above`), *System Instructions*, *API tokens*, *IPv4 addresses*, và *Canary leakage*.
    - **Vector Database Scanner (Chroma)**: So khớp độ tương đồng ngữ nghĩa (cosine similarity) với dataset chứa các câu lệnh tấn công đã biết.
    - **Transformer Model Scanner**: Sử dụng model phân loại injection.
    - **Canary Tokens**: Chèn token ngẫu nhiên vào context để phát hiện prompt leakage hoặc goal hijacking.
- **Ý nghĩa cho đề tài**: Minh chứng thực tiễn cho việc dùng YARA làm lớp lọc heuristic (Layer 1) siêu nhanh để quét các chuỗi trích xuất từ file PE/ELF trước khi chuyển tiếp cho mô hình.

---

### 2.2 NVIDIA NeMo Guardrails
- **Kho mã nguồn**: [https://github.com/NVIDIA/NeMo-Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)
- **Tài liệu chính thức**: [https://docs.nvidia.com/nemo/guardrails](https://docs.nvidia.com/nemo/guardrails)
- **Paper**: [arXiv:2310.10501](https://arxiv.org/abs/2310.10501)
- **Mô tả kỹ thuật**:
  - Framework mã nguồn mở hàng đầu về **Programmable Guardrails** cho LLM, sử dụng ngôn ngữ mô hình hóa **Colang**.
  - Chia hệ thống rào chắn thành 5 loại:
    1. **Input rails**: Chặn hoặc chuẩn hóa dữ liệu đầu vào.
    2. **Dialog rails**: Ép buộc luồng hội thoại tuân thủ quy trình chuẩn (SOP).
    3. **Retrieval rails**: Lọc bỏ các đoạn dữ liệu nhiễm độc trước khi đưa vào context.
    4. **Execution rails**: Kiểm soát nghiêm ngặt các lệnh gọi tool/API của Agent.
    5. **Output rails**: Kiểm duyệt phản hồi của mô hình (chống hallucination, phát hiện rò rỉ dữ liệu).
- **Ý nghĩa cho đề tài**: Cung cấp khung kiến trúc chuẩn công nghiệp. Đặc biệt, khái niệm **Execution Rails** giúp ngăn chặn việc Agent bị prompt injection điều khiển gọi các tool nguy hiểm (ví dụ: tự chạy lệnh shell hoặc gửi request HTTP ra ngoài).

---

### 2.3 Meta Prompt Guard (Prompt-Guard-86M) & Llama Guard
- **Model trên Hugging Face**: [https://huggingface.co/meta-llama/Prompt-Guard-86M](https://huggingface.co/meta-llama/Prompt-Guard-86M)
- **Kho mã nguồn Llama Guard**: [https://github.com/meta-llama/llama-guard](https://github.com/meta-llama/llama-guard)
- **Mô tả kỹ thuật**:
  - **Prompt-Guard-86M**: Mô hình phân loại sequence cực nhẹ (~86 triệu tham số) dựa trên kiến trúc DeBERTa-v2, được huấn luyện chuyên biệt để phát hiện 2 nhãn: *Direct Prompt Injection* và *Jailbreak*.
  - **Llama Guard 3**: Mô hình dựa trên Llama-3 chuyên kiểm tra nội dung đầu vào và đầu ra dựa trên chính sách an toàn (Content Moderation Policy).
- **Ý nghĩa cho đề tài**: Prompt-Guard-86M là ứng viên sáng giá cho **Lớp 3 (Semantic ML Guardrail)** nhờ độ trễ cực thấp, dễ dàng nhúng inline vào luồng tiền xử lý để phát hiện các biến thể injection mà YARA bỏ sót.

---

### 2.4 Protect AI LLM Guard
- **Kho mã nguồn**: [https://github.com/protectai/llm-guard](https://github.com/protectai/llm-guard)
- **Tài liệu**: [https://llm-guard.com/](https://llm-guard.com/)
- **Mô tả kỹ thuật**: Bộ công cụ scanner toàn diện cho cả Input và Output của LLM, cung cấp các scanner chuyên biệt: `PromptInjectionScanner`, `CodeScanner`, `AnonymizeScanner`.
- **Ý nghĩa cho đề tài**: Tham khảo cách thiết kế pipeline scanner lồng ghép nhiều bộ kiểm tra độc lập trước khi gửi dữ liệu đến Agent.

---

### 2.5 Guardrails AI (`guardrails-ai`)
- **Kho mã nguồn**: [https://github.com/guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails)
- **Guardrails Hub**: [https://hub.guardrailsai.com](https://hub.guardrailsai.com)
- **Mô tả kỹ thuật**: Framework định dạng và xác thực cấu trúc dữ liệu I/O của LLM (Validation Framework), đảm bảo đầu ra luôn tuân thủ cấu trúc JSON schema và chính sách bảo mật.
- **Ý nghĩa cho đề tài**: Ép Agent xuất báo cáo theo schema cố định, ngăn chặn hành vi xuất text tự do bị thao túng.

---

## 3. Công cụ Red-Teaming & Đánh giá an toàn tự động (Testing & Evaluation)

### 3.1 Microsoft PyRIT (Python Risk Identification Toolkit for GenAI)
- **Kho mã nguồn**: [https://github.com/microsoft/PyRIT](https://github.com/microsoft/PyRIT)
- **Paper**: [arXiv:2410.02828](https://arxiv.org/abs/2410.02828)
- **Mô tả kỹ thuật**: Framework tự động hóa Red-teaming của Microsoft AI Red Team, tích hợp sẵn `PromptInjectionScorer` để đo lường và kiểm thử khả năng chống chịu Indirect Prompt Injection theo chuẩn OWASP LLM01.

### 3.2 Garak (Generative AI Vulnerability Scanner)
- **Kho mã nguồn**: [https://github.com/leondz/garak](https://github.com/leondz/garak) (NVIDIA tài trợ)
- **Mô tả kỹ thuật**: Scanner tự động rà quét các lỗ hổng jailbreak, prompt injection, data exfiltration và privilege escalation.

---

## 4. Nghiên cứu học thuật & Cơ sở lý thuyết (Academic Research & Foundations)

### 4.1 Paper nền tảng về Indirect Prompt Injection (Greshake et al.)
- **Tên bài báo**: *"Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"*
- **Link**: [arXiv:2302.12173](https://arxiv.org/abs/2302.12173) (IEEE S&P / ACM CCS workshops).
- **Đóng góp cốt lõi**: Định nghĩa và chứng minh cơ chế tấn công **Indirect Prompt Injection (IPI)** thông qua dữ liệu bên ngoài (web, file, email). Khẳng định file mã độc là một kênh truyền payload tấn công Agent nguy hiểm.

### 4.2 Chứng minh toán học về sự bất toàn của Guardrail (NIST Vassilev Proof, 2026)
- **Tên bài báo**: *"Robust AI Security and Alignment: A Sisyphean Endeavor?"* (Apostol Vassilev, NIST Senior Scientist).
- **Link**: [arXiv:2512.10100](https://arxiv.org/abs/2512.10100) / IEEE Security & Privacy (2026).
- **CSA Research Note**: [https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-guardrail-incompleteness-20260615/](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-guardrail-incompleteness-20260615/)
- **Đóng góp cốt lõi**: Chứng minh toán học rằng không thể có một tập luật guardrail tĩnh nào chặn được 100% prompt tấn công trong không gian ngôn ngữ tự nhiên vô hạn. Đòi hỏi phải áp dụng mô hình phòng thủ đa tầng (**Defense-in-Depth**) và giám sát runtime liên tục.

### 4.3 Nghiên cứu về AI-SOC Neurosymbolic (arXiv:2609.10707, 2026)
- **Tên bài báo**: *"Architecting the Secure AI-SOC: A Neurosymbolic Framework for Pipeline Integrity and Threat Mitigation"*
- **Link**: [arXiv:2609.10707](https://arxiv.org/abs/2609.10707)
- **Đóng góp cốt lõi**: Đề xuất mô hình kết hợp Biểu tượng (Deterministic/Decoders) và Nơ-ron (Neural/NeMo Guardrails) để bảo vệ trung tâm điều hành an ninh mạng AI-SOC trước Promptware trong SIEM logs.

### 4.4 Nghiên cứu thực nghiệm vượt rào Guardrail (Hackett et al., 2025)
- **Tên bài báo**: *"Bypassing LLM Guardrails: An Empirical Analysis of Evasion Attacks against Prompt Injection and Jailbreak Detection Systems"*
- **Link**: [arXiv:2504.11168](https://arxiv.org/abs/2504.11168)
- **Đóng góp cốt lõi**: Thử nghiệm và chứng minh các bộ phân loại độc lập có thể bị bypass bởi các kỹ thuật chèn ký tự và biến đổi cú pháp.

---

## 5. Giải pháp & Khung bảo mật doanh nghiệp (Industry & Enterprise Solutions)

### 5.1 Microsoft Azure AI Prompt Shields & Kỹ thuật Spotlighting
- **MSRC Blog**: [How Microsoft Defends Against Indirect Prompt Injection Attacks](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)
- **Kỹ thuật Spotlighting**: Sử dụng **Delimiters** (thẻ đánh dấu biên) và **Datamarking** (chèn token ngắt quãng) để giảm thiểu ảnh hưởng của promptware ẩn trong dữ liệu (giảm thiểu rủi ro, không triệt tiêu hoàn toàn).

### 5.2 Google Cloud: Secure AI Framework (SAIF) & Model Armor
- **Trang chủ SAIF**: [https://cloud.google.com/use-cases/secure-ai-framework](https://cloud.google.com/use-cases/secure-ai-framework)
- **Model Armor**: Lớp bảo vệ proxy kiểm soát toàn bộ prompt/response trước khi chạm tới foundation model.

### 5.3 Waxell AI: Phân tích sự cố OpenClaw Agent & "The Trusted Document Problem"
- **Link**: [https://www.waxell.ai/blog/indirect-prompt-injection-enterprise-data-risk](https://www.waxell.ai/blog/indirect-prompt-injection-enterprise-data-risk)
- **Bài học**: Hơn 80% tấn công nhắm vào Agent là Indirect Prompt Injection giấu trong tài liệu/file. Bắt buộc phải có **Enforcement at Action Layer** (kiểm soát chặt chẽ ở tầng hành vi thực thi công cụ của Agent).

---

## 6. Tiêu chuẩn & Khung phân loại đe dọa (Standards & Taxonomies)

### 6.1 OWASP Top 10 for Large Language Model Applications (2025 Edition)
- **Link**: [https://genai.owasp.org/llmrisk/llm01-prompt-injection/](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- `LLM01:2025 - Prompt Injection` (Direct & Indirect IPI).
- `LLM06:2025 - Excessive Agency` (Lạm dụng quyền hạn công cụ).

### 6.2 MITRE ATLAS (Adversarial Threat Landscape for AI Systems) — Snapshot 2026.09
- **Link**: [https://atlas.mitre.org/](https://atlas.mitre.org/)
- `AML.T0051.001`: LLM Prompt Injection: Indirect.
- `AML.T0053`: AI Agent Tool Invocation.
- `AML.T0054`: LLM Jailbreak.
- `AML.T0043`: Craft Adversarial Data (nhúng promptware vào file thực thi/tài liệu).
- `AML.T0015`: Evade AI Model.
- `AML.T0056`: Extract LLM System Prompt.
- `AML.T0024.001`: Invert AI Model.

---

## 7. Kiến trúc tổng thể: Pipeline Guardrail Tĩnh & Động (End-to-End Pipeline)

```
                       ┌───────────────────────────────┐
                       │      MẪU MÃ ĐỘC ĐẦU VÀO       │
                       │     (PE / ELF / Document)     │
                       └───────────────┬───────────────┘
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        ▼ (Pha Tĩnh)                                                  ▼ (Pha Động)
┌──────────────────────────────┐              ┌──────────────────────────────────────────────┐
│ PHÂN TÍCH TĨNH (STATIC)      │              │ PHÂN TÍCH ĐỘNG (DYNAMIC / RUNTIME)           │
│ - Trích xuất Strings, PE info│              │ - Chạy trong CAPEv2 / DRAKVUF Sandbox        │
│ - YARA Rules: Quét trực tiếp │              │ - PE-sieve: Dump unpacked PE từ RAM          │
│   các chuỗi override/canary  │              │ - Trích xuất Memory Dumps & Dynamic API Logs │
└──────────────┬───────────────┘              └──────────────────────┬───────────────────────┘
               │                                                     │
               ▼                                                     ▼
┌──────────────────────────────┐              ┌──────────────────────────────────────────────┐
│ TĨNH: CAPA ABSTRACTION       │              │ ĐỘNG: YARA CUCKOO MODULE & RAM SCAN          │
│ - Chạy `capa sample.exe`     │              │ - `yara -x cuckoo=report.json rules.yar`     │
│ - Trích xuất capabilities ra │              │ - `yara rules.yar memory.dmp`                │
│   dạng JSON (MITRE ATT&CK)   │              │ - CAPA Dynamic: `capa cape_report.json`      │
└──────────────┬───────────────┘              └──────────────────────┬───────────────────────┘
               │                                                     │
               └──────────────────────┬──────────────────────────────┘
                                      │ Dữ liệu hành vi đã được làm sạch
                                      ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│ LỚP SEMANTIC ML GUARDRAIL & PROMPT ISOLATION                                               │
│ - Meta Prompt Guard-86M / Protect AI LLM Guard: Quét ngữ nghĩa các chuỗi còn sót lại       │
│ - Microsoft Spotlighting / Delimiters: Đóng gói dữ liệu trong thẻ XML nghiêm ngặt          │
│   (Phân tách Data Channel và Instruction Channel: giảm thiểu, không triệt tiêu)            │
└─────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                              │ Context đã qua kiểm soát nhiều tầng (rủi ro tồn dư)
                                              ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│ AI AGENT PHÂN TÍCH MÃ ĐỘC (LLM REASONING)                                                  │
│ - Thực hiện phân tích, lập luận và suy diễn nguy cơ                                        │
│ - Chịu sự giám sát của **NVIDIA NeMo Execution Rails** (chỉ có quyền Read, cấm Shell/Net) │
│ - Xuất báo cáo tuân thủ **Guardrails AI JSON Schema**                                      │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```
