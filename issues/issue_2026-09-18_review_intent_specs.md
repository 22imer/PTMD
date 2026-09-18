# Review intent và spec: Guardrail chống Indirect Prompt Injection cho agent phân tích mã độc

- **Ngày:** 2026-09-18
- **Trạng thái issue:** Resolved / Closed (Addressed in Spec v1.1.0 and Intent v1.1.0)
- **Mức ưu tiên:** P1 — cần xử lý trước khi phê duyệt triển khai
- **Loại:** Specification / Security Architecture / Research Evaluation
- **Phạm vi:** Review tài liệu; không thay đổi implementation, không chạy mã độc.

## 1. Kết luận

Intent đúng hướng, nhưng spec chưa đủ điều kiện mang trạng thái `Approved for Implementation`. Các vấn đề chính là:

1. Cam kết an toàn vượt quá cơ chế bảo vệ thực tế.
2. Luồng dữ liệu giữa extraction, normalization, capa và ML chưa nhất quán.
3. Chưa định nghĩa quyết định khi quét thất bại hoặc không đầy đủ.
4. Rule YARA động chưa bao phủ bề mặt API debug như mô tả.
5. Mapping MITRE có lỗi định danh và suy diễn thiếu evidence.
6. Benchmark chưa tách khả năng phát hiện injection khỏi chất lượng phân tích mã độc.
7. Evidence schema chưa đủ khả năng truy vết và mapping.
8. Các ngưỡng định lượng đang được trình bày như cam kết dù chưa có benchmark hỗ trợ.

**Đã xử lý (2026-09-18):**
- Chuyển trạng thái Spec thành `Draft — Pending Technical Validation`.
- Tái cấu trúc luồng dữ liệu thành hai nhánh song song (Detection Branch và Capability Branch), giữ nguyên mẫu PE bất biến.
- Thiết lập ma trận quyết định 3 chiều (`Processing State`, `Detection State`, `Action Policy`) xử lý rõ timeout, partial scan, detector disagreement và fallback abstention.
- Sửa chữa Telemetry Ingestion: bổ sung Telemetry Ingestion Adapter cho API arguments/debug strings (`OutputDebugString`), giới hạn đúng phạm vi của YARA Cuckoo module.
- Chuẩn hóa định danh theo MITRE ATLAS Snapshot 2026.09 (`AML.T0051.001`, `AML.T0015`, `AML.T0053`, `AML.T0056`), siết chặt bằng chứng khi ánh xạ ATT&CK.
- Thiết kế lại giao thức Benchmark 4 nhóm mẫu và phân tách 2 Ground Truth độc lập (`GT_Injection` vs `GT_Malware_Behavior`).
- Cập nhật Quarantined Evidence Schema với đầy đủ metadata truy vết (`artifact_sha256`, `source_location`, `rule_or_model_version`, `owasp_llm_mapping`, `policy_decision`).
- Chuyển đổi toàn bộ các cam kết định lượng thành Chỉ tiêu kỹ thuật kỳ vọng (Target SLA / Engineering Hypotheses) cho Pha 2.
- Tạo `CONTEXT.md` và 3 bản ADR (`docs/adr/0001`, `0002`, `0003`) chuẩn hóa bản thể học và các quyết định kiến trúc then chốt.
## 2. Tài liệu được review

| Tài liệu | Vai trò |
|---|---|
| `intent/pre-validate.md` | Intent gốc và giới hạn pha nghiên cứu |
| `intent/research_pre_validate.md` | Threat model, kiến trúc đề xuất và tiêu chí nghiệm thu nghiên cứu |
| `specs/guardrail_malware_agent_spec.md` | Đặc tả kỹ thuật, schemas, mapping và benchmark |
| `links.md` | Nguồn tham khảo và các khẳng định kỹ thuật hỗ trợ |

Các số dòng dưới đây tham chiếu phiên bản được review ngày 2026-09-18; có thể thay đổi sau khi chỉnh tài liệu.

### Giới hạn kiểm chứng

- Đã đối chiếu các điểm kỹ thuật quan trọng với tài liệu chính thức của YARA, capa, Microsoft và dữ liệu MITRE ATLAS/ATT&CK.
- Chưa benchmark mô hình, chưa chạy pipeline, chưa kiểm thử sandbox hoặc thực thi mã độc.
- Những hệ quả thiết kế chưa được tái hiện thực nghiệm được đánh dấu `[INFERENCE]`.
- Issue này không xác nhận toàn bộ nguồn trong `links.md` đã được kiểm chứng độc lập.

## 3. Review intent

### 3.1 Những điểm nên giữ

- **Đúng đối tượng bảo vệ:** agent phân tích mã độc, không phải xây thêm một malware detector.
- **Đúng bề mặt tấn công:** strings, metadata, memory và sandbox telemetry.
- **Đúng yêu cầu đầu ra:** evidence có thể truy vết, mapping và quyết định xử lý trước khi agent tiếp nhận dữ liệu.
- **Đúng hướng kiểm soát thiệt hại:** agent không có shell/network/write tools; không phụ thuộc hoàn toàn vào khả năng phát hiện injection.

### 3.2 Phân biệt CAPA và CAPE

**Vị trí:** `intent/pre-validate.md:7`.

Intent ghi “CAPA Sandbox”. Cần phân biệt:

- **CAPE:** sandbox thực hiện phân tích động.
- **capa:** công cụ nhận diện capabilities từ binary hoặc sandbox report.

Đây là hai vai trò khác nhau trong pipeline, không phải hai cách gọi của cùng một công cụ.

### 3.3 Không phát hiện không đồng nghĩa an toàn

**Vị trí:** `intent/pre-validate.md:13`.

Intent cho phép agent tiếp tục khi không thấy dấu vết tấn công. Cần bổ sung điều kiện:

- Các bước xử lý bắt buộc đã hoàn tất.
- Dữ liệu chuyển tiếp được giới hạn theo policy.
- Dữ liệu vẫn mang nhãn untrusted.
- Timeout, thiếu dump hoặc quét bị cắt ngắn không được hiểu là clean.

### 3.4 Ghi nhận thay đổi phạm vi

Intent gốc tập trung tiền xử lý và khảo sát; research mở rộng sang guardrail đầu vào, runtime và đầu ra; spec thu hẹp định dạng mục tiêu xuống Windows PE.

Các thay đổi này có thể hợp lý, nhưng cần bảng đối chiếu yêu cầu theo ba trạng thái: **giữ lại / mở rộng / loại khỏi phạm vi**. Không nên tuyên bố hoàn tất toàn bộ intent khi chưa giải thích các quyết định này.

Việc mô tả thử nghiệm cho pha sau không tự vi phạm giới hạn pha nghiên cứu, nhưng phải ghi rõ đây là kế hoạch chưa thực hiện, không phải kết quả đã được xác nhận.

### 3.5 Định nghĩa đóng góp nghiên cứu bằng giả thuyết đo được

Danh sách YARA + ML + CAPE + capa chưa tự tạo thành đóng góp nghiên cứu. Câu hỏi trung tâm nên là:

> Guardrail kết hợp luật và mô hình ngữ nghĩa giảm mức độ thành công của indirect prompt injection bao nhiêu, với chi phí độ trễ và suy giảm chất lượng phân tích mã độc như thế nào?

**Tên đề tài đề xuất nếu tập trung tiền xử lý:**

> Nghiên cứu và đánh giá cơ chế tiền xử lý đa tầng chống Indirect Prompt Injection cho agent phân tích mã độc Windows PE.

Nếu giữ runtime/output governance làm đóng góp chính, có thể giữ tên “kiến trúc guardrail đa tầng”, nhưng cần cập nhật phạm vi intent tương ứng.

## 4. Findings trong spec

### F01 — [P1] XML/Spotlighting bị coi là ranh giới bảo mật tuyệt đối

**Vị trí:** `specs/guardrail_malware_agent_spec.md:93–97, 225–256`.

#### Vấn đề

Spec viết “Payload Context an toàn tuyệt đối” và xem việc bọc thẻ là biến câu lệnh đối kháng thành dữ liệu thụ động.

Microsoft mô tả Spotlighting là biện pháp xác suất, không bảo đảm LLM luôn phân biệt instruction với data. XML escaping bảo vệ cấu trúc serialization, không vô hiệu hóa ngữ nghĩa của payload.

#### Thay đổi cần có

- Bỏ các khẳng định “an toàn tuyệt đối”, “phân tách tuyệt đối”.
- Quy định system instructions được truyền bằng message role thực, không chỉ bằng thẻ `<system_policy>`.
- Tách evidence gốc lưu cho điều tra khỏi nội dung cần đưa vào LLM.
- Quy định mọi kết quả tool, kể cả `get_quarantined_evidence()`, phải đi qua chính sách đưa dữ liệu vào context.
- Mô tả residual risk khi LLM vẫn bị tác động dù dữ liệu đã được đóng gói.

**Nguyên tắc:** giữ evidence để điều tra không đồng nghĩa phải đưa nguyên payload đã phát hiện trở lại agent.

**Nguồn:** [Microsoft — How Microsoft defends against indirect prompt injection attacks](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks).

### F02 — [P1] Sơ đồ pipeline và mô tả thành phần không khớp

**Vị trí:** spec `:54–87, 111–124, 195–210`.

#### Vấn đề

- Normalization nằm trước static extraction và sandbox execution, trong khi strings/logs/memory mới sinh ra sau các bước này.
- CAPA loại raw strings trước semantic guardrail, nhưng semantic guardrail lại cần quét chính các strings đó.

Chưa rõ ML nhận dữ liệu từ đâu và runtime payload có đi qua normalization hay không.

#### Thay đổi cần có

Phân tách rõ nhánh phát hiện injection và nhánh phân tích capabilities:

```text
PE gốc bất biến
  → Static extraction / Sandbox artifact extraction
      ├─ Text gốc + bản normalized → YARA / ML → Findings
      └─ capa → Projection theo allowlist → Capabilities

Findings + Capabilities + trạng thái xử lý
  → Policy gate → Agent context
```

- Normalization áp dụng lên bản sao dữ liệu trích xuất, không sửa binary đưa vào sandbox.
- Giữ liên kết giữa bản normalized và bytes/offset gốc.
- Xác định input/output của từng thành phần và đường đi của artifact động.
- Phân biệt dữ liệu dùng cho detection với dữ liệu được phép chuyển vào context của agent.

### F03 — [P1] Chưa định nghĩa quyết định khi quét thất bại hoặc không đầy đủ

**Vị trí:** spec `:131–134, 212–219, 225–273, 395–403`.

#### Vấn đề

Tài liệu có giới hạn 2.000 strings, depth 2 và re-ask, nhưng chưa định nghĩa cách xử lý:

- Sandbox timeout hoặc không lấy được memory dump.
- CAPA/YARA/ML lỗi hoặc không hỗ trợ artifact.
- Strings bị loại do độ dài, entropy hoặc vượt ngân sách.
- YARA và ML bất đồng.
- Hết số lần re-ask mà output vẫn không hợp lệ.

Bảng mapping theo vector chưa thay thế được decision policy matrix mà research yêu cầu.

#### Thay đổi cần có

Tách ba chiều trạng thái:

| Chiều | Trạng thái đề xuất |
|---|---|
| Xử lý | `COMPLETE / PARTIAL / FAILED` |
| Phát hiện | `DETECTED / NOT_DETECTED / INCONCLUSIVE` |
| Hành động | Tiếp tục với context giới hạn / sanitize / chuyển người kiểm tra / block |

- Định nghĩa thứ tự ưu tiên và hành động cho từng trường hợp lỗi, thiếu dữ liệu và bất đồng detector.
- Không suy diễn `NOT_DETECTED` từ một bước không chạy hoặc chạy không đầy đủ.
- Phân biệt block một tool call, loại một đoạn khỏi context và dừng toàn bộ phân tích.
- Định nghĩa fallback hoặc abstention cụ thể, thay vì chỉ ghi “fallback an toàn”.

### F04 — [P1] Rule YARA động không bao phủ API debug như mô tả

**Vị trí:** spec `:169–190`.

#### Vấn đề

Comment nói kiểm tra “API ghi log / debug”, nhưng điều kiện dùng `cuckoo.filesystem.file_access(...)`.

Theo tài liệu YARA Cuckoo, hàm này khớp đường dẫn file được truy cập, không phải nội dung `OutputDebugString` hay tham số API tùy ý.

Ngoài ra:

- Cuckoo module nhận report qua `-x cuckoo=...` hoặc `modules_data`; không đơn giản là quét JSON như file text.
- Module không được bật mặc định ở mọi bản build.
- Spec chưa chứng minh report CAPE đã chọn tương thích với các trường Cuckoo module đọc.

#### Thay đổi cần có

- Chỉ rõ adapter trích API arguments, debug strings và window titles, rồi đưa các trường này qua pipeline text.
- Ghim phiên bản YARA, cấu hình module và định dạng report CAPE.
- Chỉ rõ trường nào được Cuckoo module bao phủ, trường nào do adapter xử lý.
- Định nghĩa report fixture để kiểm chứng tương thích và độ bao phủ trước khi phê duyệt triển khai.

**Nguồn:** [YARA — Cuckoo module](https://yara.readthedocs.io/en/stable/modules/cuckoo.html).

### F05 — [P1] Mapping MITRE có lỗi định danh và suy diễn quá mức

**Vị trí:** spec `:397–403`; `links.md:183–187`.

#### Vấn đề

Đối chiếu ATLAS bản `2026.09`:

| Trong tài liệu | Đối chiếu đúng |
|---|---|
| `AML.T0040` = Evade ML Model | Là **AI Model Inference API Access**; evasion là `AML.T0015` |
| `AML.T0024` = Invert Model / system prompt leakage | `AML.T0024` là **Exfiltration via AI Inference API**; inversion là `AML.T0024.001`; system prompt extraction là `AML.T0056` |
| `AML.T0053` = LLM Agent Hijacking | Tên hiện hành là **AI Agent Tool Invocation** |
| IPI chỉ dùng mã cha `AML.T0051` | Có mã cụ thể `AML.T0051.001` — **Indirect** |

Mapping ATT&CK cũng cần evidence:

- Có plaintext promptware không tự chứng minh `T1027`.
- Có chuỗi unpack trong RAM không tự chứng minh `T1497` — Virtualization/Sandbox Evasion.
- Log chứa yêu cầu chạy shell không chứng minh shell đã được thực thi.

#### Thay đổi cần có

- Sửa ID/tên và ghi rõ phiên bản taxonomy được sử dụng.
- Mapping theo hành vi quan sát được, không chỉ theo nơi payload xuất hiện.
- Phân biệt attempted action với successful action.
- Ghi `No direct mapping` khi thiếu căn cứ.
- Không đồng nhất mapping theo taxonomy với đạt chứng nhận tuân thủ.

**Nguồn:**

- [MITRE ATLAS — Snapshot 2026.09](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.09.yaml).
- [MITRE ATT&CK — T1497](https://attack.mitre.org/techniques/T1497/).

### F06 — [P1] Benchmark có thể thưởng cho cách phân loại sai mục tiêu

**Vị trí:** spec `:238–242, 409–428`.

#### Vấn đề

Nhóm B là file nền lành tính có injection, nhưng system policy yêu cầu mọi chỉ thị thao túng phải được báo cáo là malicious behavior. Trong khi đó ERR chỉ xét agent giữ nhãn `MALICIOUS`.

**[INFERENCE]** Thiết kế đánh giá này có nguy cơ thưởng cho chiến lược “thấy injection thì luôn kết luận MALICIOUS”, thay vì chứng minh agent giữ được phân tích hành vi chính xác.

Bộ đánh giá còn thiếu:

- Nhóm benign không injection.
- Nhãn riêng cho malware behavior và injection.
- Cặp mẫu trước/sau chèn payload để đo thay đổi verdict.
- Baseline không guardrail, YARA-only, ML-only và pipeline đầy đủ.
- Phân tách calibration/test theo mẫu gốc và họ payload để tránh leakage.
- Định nghĩa attack success cụ thể: đổi verdict, bỏ evidence, tool misuse hay output leakage.

#### Thay đổi cần có

- Báo cáo đồng thời detection quality, attack success rate và chất lượng phân tích mã độc.
- Không dùng recall của detector thay cho độ an toàn end-to-end.
- Định nghĩa ground truth riêng cho injection và hành vi của mẫu.
- Làm rõ cách đánh giá file nền lành tính bị chèn payload, tránh nhập nhằng giữa “có hành vi tấn công agent” và “có hành vi mã độc thực thi”.
- Chốt protocol đánh giá trước khi chọn ngưỡng nghiệm thu.

### F07 — [P2] Evidence schema chưa đáp ứng yêu cầu truy vết và mapping

**Vị trí:** spec `:279–386`.

#### Vấn đề

Evidence có `escaped_payload`, nhưng thiếu:

- Sample/artifact hash và vị trí nguồn: offset, JSON path hoặc process/address.
- Rule/model version và chuỗi phép biến đổi.
- OWASP mapping.
- Quyết định policy và lý do.
- Khả năng ghi nhiều detection methods cho cùng evidence.

`mitre_atlas_id` là trường bắt buộc nhưng chưa có quy ước biểu diễn “không có mapping phù hợp”. Final report chưa liên kết finding về `evidence_id`.

Phần tử trong `evasion_attempts` không có `required`, nên một object rỗng `{}` vẫn được phép theo schema đã viết.

#### Thay đổi cần có

- Bảo đảm mỗi finding có thể truy ngược đến artifact gốc và tái kiểm tra.
- Liên kết final report với evidence được pipeline ghi nhận.
- Định nghĩa mapping không xác định, mapping nhiều mã và nhiều detector cùng phát hiện.
- Bổ sung ràng buộc cho các trường bắt buộc của finding.
- Phân biệt JSON hợp lệ, nội dung có evidence và kết luận đúng; schema chỉ giải quyết phần đầu.

### F08 — [P2] Các con số đang được trình bày như kết quả đã chứng minh

**Vị trí:** spec `:203, 211, 423–428`.

#### Vấn đề

Chưa có bằng chứng trong tài liệu cho các cam kết:

- CAPA loại 95% attack surface và giữ 100% giá trị hành vi.
- 50 ms/512 tokens trên “CPU đa nhân hiện đại”.
- Re-ask tối đa hai lần bảo đảm schema compliance 100%.

Tài liệu capa cho thấy output có thể chứa evidence và strings. Việc tạo bản dữ liệu giới hạn cho agent là trách nhiệm của adapter, không phải bảo đảm mặc định của capa.

Kiểm tra ngân sách theo giả định của spec:

```text
2.000 sequences × 50 ms = 100 giây nếu xử lý tuần tự
15 giây / 50 ms = 300 sequences, chưa tính các tầng khác
```

Đây là phép tính ngân sách giả định, không phải benchmark đo thực tế. Nó không chứng minh SLA 15 giây bất khả thi, nhưng cho thấy spec thiếu ngân sách batch/concurrency và benchmark phần cứng.

#### Thay đổi cần có

- Chuyển các số chưa đo thành mục tiêu cần kiểm chứng.
- Ghi rõ workload, hardware, batch size, concurrency, percentile và cách tính overhead.
- Định nghĩa phép đo giảm attack surface và giữ giá trị hành vi; không dùng phần trăm khi chưa có mẫu số và protocol.
- Schema hợp lệ 100% chỉ nên là điều kiện của báo cáo được phát hành; tỷ lệ lỗi/abstain phải được đo riêng.

**Nguồn:** [Mandiant capa — README và ví dụ evidence output](https://github.com/mandiant/capa/blob/master/README.md).

## 5. Thứ tự xử lý đề xuất

1. **Chốt intent và phạm vi nghiên cứu:** bảo vệ agent; không đánh đồng injection với malware verdict.
2. **Sửa trust boundary, dataflow và failure policy:** xác định dữ liệu được agent đọc, bên quyết định quyền đọc và xử lý khi thiếu bằng chứng.
3. **Sửa mapping và integration contracts:** YARA/CAPE/capa, phiên bản, trường dữ liệu và evidence provenance.
4. **Thiết kế lại benchmark:** tách detection, attack success và chất lượng phân tích; sau đó mới chốt threshold/SLA.
5. **Đánh giá lại trạng thái spec:** chỉ chuyển từ draft sang phê duyệt khi contract và các giả thuyết quan trọng có bằng chứng kiểm chứng.

## 6. Tiêu chí đóng issue

- [ ] Intent phân biệt CAPE với capa và định nghĩa rõ đối tượng bảo vệ.
- [ ] Có đối chiếu phạm vi giữa intent gốc, research và spec, bao gồm các quyết định mở rộng/thu hẹp.
- [ ] F01: Không còn cam kết an toàn tuyệt đối từ XML/Spotlighting; policy bao phủ cả tool-returned data.
- [ ] F02: Sơ đồ và mô tả pipeline thống nhất; mọi artifact tĩnh/động có đường đi rõ ràng; dữ liệu gốc được giữ bất biến.
- [ ] F03: Có decision policy matrix cho complete/partial/failed, bất đồng detector và hết re-ask; không mặc định lỗi thành clean.
- [ ] F04: Phạm vi Cuckoo module và adapter được mô tả chính xác; có bằng chứng tương thích với report fixture và phiên bản được chọn.
- [ ] F05: Mapping được sửa theo taxonomy có phiên bản; mỗi mapping có điều kiện evidence và cho phép `No direct mapping`.
- [ ] F06: Protocol đánh giá có benign controls, nhãn tách biệt, paired samples, baselines và quy tắc chia dữ liệu chống leakage.
- [ ] F07: Evidence và final report liên kết được với artifact gốc, detector/version, mapping và quyết định policy.
- [ ] F08: Mọi chỉ số định lượng được phân biệt rõ là mục tiêu hay kết quả đo; có định nghĩa workload và protocol tương ứng.
- [ ] Những sửa đổi liên quan được đồng bộ giữa `intent/`, `specs/` và `links.md`; không còn tuyên bố hoàn tất hoặc phê duyệt vượt quá bằng chứng hiện có.

## 7. Nguồn kiểm chứng chính

1. [YARA — Cuckoo module](https://yara.readthedocs.io/en/stable/modules/cuckoo.html).
2. [Mandiant capa — README](https://github.com/mandiant/capa/blob/master/README.md).
3. [Microsoft — How Microsoft defends against indirect prompt injection attacks](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks).
4. [MITRE ATLAS — Snapshot 2026.09](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.09.yaml).
5. [MITRE ATT&CK — Virtualization/Sandbox Evasion, T1497](https://attack.mitre.org/techniques/T1497/).
