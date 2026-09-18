# Spec v1.2.0 chưa đáp ứng đầy đủ tiêu chí đóng issue review intent/specs

- **Ngày:** 2026-09-19
- **Trạng thái:** Resolved / Closed — tái xác nhận 2026-09-19 trên Spec v1.4.0 (T00 v2: 8/8 CLOSED; `reports/phase0-gate.json`, §7).
- **Ưu tiên:** P1
- **Loại:** Specification / Security Architecture / Data Contracts / Evaluation Protocol
- **Issue liên quan:** [Review intent và specs ngày 2026-09-18](issue_2026-09-18_review_intent_specs.md)
- **Phiên bản được kiểm tra:** `specs/guardrail_malware_agent_spec.md` v1.2.0; research intent v1.2.0. *(Bản gốc của review F01–F08; bản hiện hành và tái kiểm xem §7.)*

## 1. Kết luận

Toàn bộ 8 điểm chặn kỹ thuật (R01–R08) đã được xử lý triệt để và đồng bộ trên toàn bộ hệ thống tài liệu:
- `specs/guardrail_malware_agent_spec.md` đã được nâng cấp lên **Phiên bản 1.3.0** (sau đó **1.4.0** — xem §7).
- `CONTEXT.md`, `docs/adr/0002-tag-as-evidence-over-hard-block.md` và `links.md` đã được loại bỏ 100% các tuyên bố "an toàn tuyệt đối" và đồng bộ hóa danh mục MITRE ATLAS Snapshot 2026.09.
- Đã bổ sung tệp fixture kiểm chứng tương thích: `tests/fixtures/cape_report_sample_harmless.json`.
- Trạng thái issue chuyển sang **Resolved / Closed**. Đủ điều kiện để tiến hành tạo `AGENTS.md` khi người dùng yêu cầu.

## 2. Phạm vi và bằng chứng kiểm tra

Đã đối chiếu:

- `issues/issue_2026-09-18_review_intent_specs.md`, bao gồm toàn bộ tiêu chí đóng issue.
- `specs/guardrail_malware_agent_spec.md`.
- `intent/pre-validate.md` và `intent/research_pre_validate.md`.
- `links.md`, `CONTEXT.md` và ba tài liệu trong `docs/adr/`.

Kiểm tra thực hiện:

1. Chạy riêng hàm `evaluate_policy_gate()` trích từ spec với 9 tổ hợp của `COMPLETE / PARTIAL / FAILED` và `DETECTED / NOT_DETECTED / INCONCLUSIVE`.
2. Parse thành công 3 JSON blocks trong spec.
3. Đối chiếu các action do policy gate trả về với enum `policy_decision` trong evidence schema.
4. Tìm artifact fixture/test/benchmark/validation trong repository; chưa tìm thấy report fixture tương ứng để chứng minh tích hợp YARA/CAPE.

**Giới hạn:** chưa chạy validator JSON Schema đầy đủ, chưa chạy pipeline hoặc benchmark và không thực thi mã độc. Những kết quả trên không phải bằng chứng rằng hệ thống đã vận hành an toàn.

Các số dòng dưới đây thuộc snapshot được kiểm tra ngày 2026-09-19 và có thể thay đổi sau khi chỉnh tài liệu.

## 3. Ma trận trạng thái F01–F08

| Finding | Trạng thái | Phần đã cải thiện | Phần còn chặn đóng issue |
|---|---|---|---|
| F01 — Trust boundary | Partial | Có residual-risk statement, message role `system`, tách raw evidence khỏi context | Thiếu contract cho tool-returned data; ADR/glossary còn khẳng định an toàn tuyệt đối |
| F02 — Dataflow | Partial | Tách Detection/Capability branches, giữ PE bất biến | Adapter trích text ở Lớp 1, sau Normalization Lớp 0; chưa chỉ rõ đường đưa text mới trích qua normalization |
| F03 — Failure policy | Partial | Có các nhánh `FAILED`, `PARTIAL`, `COMPLETE` | `PARTIAL` bỏ qua detection state; chưa chốt sanitization/escalation, xử lý bất đồng detector và kết quả sau re-ask |
| F04 — Telemetry/YARA | Partial | Có adapter cho API debug/window/message strings | Thiếu phiên bản tích hợp, report schema và fixture/bằng chứng tương thích |
| F05 — MITRE mapping | Partial | Sửa các ID chính và bổ sung một số điều kiện evidence | Tài liệu liên quan còn mapping cũ; quyền gọi shell chưa đủ chứng minh thực thi shell |
| F06 — Benchmark | Partial | Có 4 nhóm mẫu và 2 ground truth độc lập | Thiếu paired samples, split chống leakage, các baseline và định nghĩa attack success đầy đủ |
| F07 — Evidence schema | Partial | Có artifact hash, source location, nhiều detector, evidence reference | Thiếu transform chain, multi-ATLAS/no-mapping contract và quan hệ giữa action vocabularies |
| F08 — Chỉ số định lượng | Partial | Đã chuyển các số thành mục tiêu cần kiểm chứng | Thiếu cấu hình đo tái lập và cách đo abstention riêng |

## 4. Các điểm còn tồn tại

### R01 — [P1] Policy gate chưa bảo toàn thông tin phát hiện khi xử lý không đầy đủ

**Liên quan:** F03, F07.

**Vị trí:** `specs/guardrail_malware_agent_spec.md:285–330, 417–420`.

Kết quả thực chạy với `PARTIAL + DETECTED`:

```json
{
  "action": "ESCALATE_AND_INCONCLUSIVE",
  "forward_to_agent": true,
  "confidence_penalty": 0.3,
  "add_flag": "TRUNCATED_ARTIFACT_WARNING",
  "reason": "Artifact budget exceeded or timeout occurred; untrusted data may contain uninspected promptware."
}
```

Cả ba giá trị detection state dưới `PARTIAL` đều trả về cùng một kết quả. Nhánh này chưa chỉ rõ cách bảo toàn positive finding, sanitization bắt buộc và hành động escalation cụ thể.

Evidence schema chỉ cho phép:

```text
TAG_AS_EVIDENCE
SANITIZE_AND_STRIP
HARD_BLOCK
ESCALATE_TO_HUMAN
```

Trong khi policy gate còn trả về:

```text
ALLOW
CAUTIOUS_QUARANTINE
ESCALATE_AND_INCONCLUSIVE
PIPELINE_ABSTENTION
```

Không bắt buộc mọi quyết định cấp pipeline phải trở thành quyết định cấp evidence. Tuy nhiên, nếu đây là hai khái niệm khác nhau, spec cần định nghĩa rõ phạm vi và phép chuyển đổi, thay vì để người triển khai tự suy diễn.

**Yêu cầu sửa:**

- Quy định rõ `PARTIAL + DETECTED`: giữ finding đã phát hiện, phân biệt phần đã kiểm tra với phần chưa kiểm tra và xác định dữ liệu được chuyển tiếp.
- Chỉ rõ sanitization và escalation cho từng nhánh; không dựa duy nhất vào tên action.
- Định nghĩa quy tắc tổng hợp detector results và trạng thái bất đồng.
- Thống nhất action vocabulary hoặc mô tả mapping giữa pipeline policy và evidence policy.
- Bổ sung contract cho kết quả sau khi hết re-ask: lỗi, abstention hoặc báo cáo giới hạn; không ép trường hợp chưa đủ bằng chứng thành `BENIGN`.

### R02 — [P1] Trust boundary chưa được áp dụng nhất quán trong tài liệu

**Liên quan:** F01 và tiêu chí đồng bộ tài liệu.

**Vị trí:**

- `specs/guardrail_malware_agent_spec.md:100–108, 333–350`.
- `docs/adr/0002-tag-as-evidence-over-hard-block.md:4–7`.
- `CONTEXT.md:39–49`.
- `links.md:48, 162, 225`.

Spec đã có message role thực và quy định raw evidence chỉ lưu ở kho điều tra. Tuy nhiên, contract áp dụng policy cho mọi dữ liệu trả về từ các hàm truy vấn chưa được đặc tả.

Các tài liệu liên quan vẫn viết:

- CAPA loại bỏ **100%** chuỗi tự do độc hại.
- Tag-as-Evidence vô hiệu hóa câu lệnh mà **không gây nguy hiểm cho Agent**.
- Escaping và prompt isolation phải hoạt động **tuyệt đối an toàn**.
- Context sau pipeline là **an toàn tuyệt đối**.

Những khẳng định này mâu thuẫn với residual-risk statement và mô hình giảm thiểu rủi ro trong spec.

**Yêu cầu sửa:**

- Định nghĩa dữ liệu tool trả về phải qua context ingress policy; quyền read-only không tự làm nội dung trả về đáng tin cậy.
- Phân biệt bảo vệ cấu trúc serialization với khả năng LLM vẫn bị ảnh hưởng bởi ngữ nghĩa.
- Đồng bộ spec, glossary, ADR và tài liệu nguồn theo cùng một trust model.
- Phân biệt evidence gốc dành cho điều tra và metadata/summary được phép đưa vào agent context.

### R03 — [P1] Đường đi của telemetry qua normalization chưa rõ

**Liên quan:** F02.

**Vị trí:** `specs/guardrail_malware_agent_spec.md:70–84, 119–132, 219–248`.

Sơ đồ đặt Normalization ở Lớp 0, sau đó mới đến Lớp 1 chứa Telemetry Ingestion Adapter. Adapter lại là thành phần tạo ra `raw_string` từ API arguments.

Spec chưa chỉ rõ text mới được adapter trích xuất phải quay lại Lớp 0 hay adapter thực chất thuộc bước extraction phía trước Lớp 0. Đây là điểm còn thiếu trong đường đi của artifact động, dù việc tách Detection/Capability branches đã được sửa.

**Yêu cầu sửa:**

- Đặt adapter ở vị trí nhất quán với nhiệm vụ extraction hoặc mô tả rõ cạnh dữ liệu đưa output của adapter qua normalization.
- Xác định contract từ API argument đến normalized text, findings và agent context.
- Định nghĩa cách giữ provenance cho log bằng JSON pointer/process information, không chỉ integer file offset.
- Bảo đảm sơ đồ và mô tả từng thành phần cùng biểu diễn một pipeline.

### R04 — [P1] Chưa có bằng chứng tương thích YARA/CAPE và phạm vi module còn mô tả sai

**Liên quan:** F04.

**Vị trí:** `specs/guardrail_malware_agent_spec.md:214–248`.

Đã có adapter chuyên biệt, nhưng chưa ghim phiên bản YARA, CAPE và cấu trúc report. Chưa tìm thấy report fixture hoặc kết quả kiểm chứng tương thích tương ứng.

Tại dòng 220, spec viết YARA Cuckoo module “chỉ hỗ trợ kiểm tra URL và network headers”. Mô tả này quá hẹp: tài liệu chính thức còn có các hàm kiểm tra filesystem, registry và mutex. Điểm cần phân biệt là module không thay thế bộ trích xuất API arguments tùy ý.

**Yêu cầu sửa:**

- Mô tả đúng phạm vi module và phạm vi adapter.
- Ghim phiên bản/build options/report schema hoặc commit tương ứng.
- Chỉ rõ cơ chế truyền report vào Cuckoo module và xử lý report không tương thích.
- Bổ sung fixture vô hại, nguồn/phiên bản fixture và kết quả đối chiếu các trường cần đọc.
- Kiểm chứng bằng fixture không đòi hỏi chạy mã độc sống.

**Nguồn:** [YARA — Cuckoo module](https://yara.readthedocs.io/en/stable/modules/cuckoo.html).

### R05 — [P1] Mapping chưa đồng bộ và vẫn thiếu điều kiện hành vi

**Liên quan:** F05.

**Vị trí:**

- `specs/guardrail_malware_agent_spec.md:508–514`.
- `links.md:183–187`.
- `docs/adr/0002-tag-as-evidence-over-hard-block.md:4`.

Spec đã sửa các ID chính nhưng:

- `links.md` vẫn gọi `AML.T0053` là “LLM Agent Hijacking”.
- `links.md` vẫn gộp `AML.T0040 / AML.T0015` thành “Evade ML Model”.
- ADR-0002 vẫn gán `T1497` mặc định cho promptware.
- Dòng 512 của spec cho phép gán `T1059.003` khi Agent có quyền shell; quyền hạn chưa phải bằng chứng Windows Command Shell đã được thực thi.

**Yêu cầu sửa:**

- Đồng bộ ID/tên theo snapshot ATLAS 2026.09.
- Tách observed instruction, attempted tool invocation và executed action.
- Chỉ gán ATT&CK khi có evidence hành vi đáp ứng điều kiện; ghi `No direct mapping` khi không đủ căn cứ.

**Nguồn đối chiếu:**

- [MITRE ATLAS — Snapshot 2026.09](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.09.yaml).
- [MITRE ATT&CK — T1497](https://attack.mitre.org/techniques/T1497/).

### R06 — [P1] Bốn nhóm benchmark chưa tạo thành protocol đánh giá đầy đủ

**Liên quan:** F06.

**Vị trí:** `specs/guardrail_malware_agent_spec.md:520–540`.

Đã có nhóm benign không injection và hai ground truth độc lập. Tuy nhiên, các yêu cầu sau của issue gốc chưa được định nghĩa:

- Ghép cặp mẫu trước/sau chèn payload và cách xác nhận hành vi nền không đổi.
- Chia calibration/test theo mẫu gốc và họ payload để tránh leakage.
- Cấu hình so sánh no-guardrail, YARA-only, ML-only và pipeline đầy đủ.
- Định nghĩa attack success cho đổi verdict, bỏ evidence, tool misuse và output leakage.

Công thức mang tên `Baseline Malware Classification Accuracy` hiện đo tỷ lệ kết luận đúng trên Nhóm 2; riêng công thức đó chưa xác định một baseline hệ thống để so sánh với guardrail.

**Yêu cầu sửa:** bổ sung protocol, đơn vị đo, ground truth, cách chia tập và cấu hình so sánh trước khi nghiệm thu các mục tiêu định lượng.

Không yêu cầu hoàn thành toàn bộ benchmark để chấp nhận research draft; yêu cầu ở đây là thiết kế kiểm chứng phải đủ rõ và tái lập được.

### R07 — [P2] Evidence contract chưa giữ đủ provenance và biểu diễn mapping

**Liên quan:** F07.

**Vị trí:** `specs/guardrail_malware_agent_spec.md:128–170, 364–421, 477–486`.

Đã bổ sung artifact hash, source location, nhiều detector và `evidence_reference_id`. Những phần còn thiếu:

- Evidence schema chưa có transform chain liên kết raw representation với normalized representation.
- `mitre_atlas_mapping` là một object duy nhất, trong khi bảng mapping có trường hợp cần nhiều ATLAS IDs.
- Chưa có quy ước ATLAS no-mapping rõ ràng; chỉ OWASP có giá trị `No direct mapping` được định nghĩa.
- Quan hệ giữa `policy_decision` và action của policy gate chưa được đặc tả, như R01.

**Yêu cầu sửa:**

- Định nghĩa lưu trữ và liên kết provenance đủ để tái kiểm tra finding.
- Hỗ trợ multi-mapping/no-mapping một cách nhất quán với bảng tiêu chuẩn.
- Bảo đảm final report tham chiếu được evidence thực sự tồn tại.
- Phân biệt JSON đúng cấu trúc, finding có evidence và kết luận đúng; không coi schema validation là kiểm chứng ngữ nghĩa.

### R08 — [P2] Chưa định nghĩa phép đo tái lập cho các mục tiêu kỹ thuật

**Liên quan:** F08.

**Vị trí:** `specs/guardrail_malware_agent_spec.md:268, 542–553`.

Việc đổi các con số từ cam kết sang target hypothesis là đúng hướng, nhưng chưa đủ tiêu chí gốc về workload và protocol.

Còn thiếu:

- Cấu hình CPU/GPU và runtime thực nghiệm.
- Batch size, concurrency và ngân sách số chuỗi/sequences.
- Percentile, ranh giới đo latency và định nghĩa raw pipeline dùng làm đối chứng.
- Cách tính schema compliance riêng với tỷ lệ abstention/lỗi.

Mục tiêu schema compliance 100% “với Fallback Abstention” chưa chỉ rõ denominator và hình dạng output của abstention. Final report hiện chỉ có verdict `MALICIOUS / SUSPICIOUS / BENIGN`.

**Yêu cầu sửa:** định nghĩa cấu hình đo và kết quả fallback; giữ mọi số chưa đo ở trạng thái mục tiêu, không trình bày như kết quả đã xác nhận.

## 5. Thứ tự xử lý đề xuất

1. Sửa policy và data contracts: R01, R07.
2. Làm rõ trust boundary và dataflow: R02, R03.
3. Chốt tích hợp bằng fixture và sửa mapping: R04, R05.
4. Hoàn thiện evaluation protocol và cấu hình đo: R06, R08.
5. Đồng bộ trạng thái issue và tài liệu liên quan; kiểm tra lại toàn bộ trước khi tạo `agents.md`.

## 6. Tiêu chí đóng issue

- [x] R01: Từng tổ hợp processing/detection state có hành động rõ ràng; positive finding được bảo toàn; sanitization, escalation, detector disagreement và fallback có contract nhất quán.
- [x] R02: Tool-returned data được bao phủ bởi ingress policy; spec, glossary, ADR và links không còn cam kết an toàn tuyệt đối từ escaping/Spotlighting.
- [x] R03: Có đường dữ liệu rõ ràng từ telemetry extraction qua normalization đến findings; provenance hỗ trợ file, memory và log.
- [x] R04: Phiên bản tích hợp/report schema được ghim; có fixture vô hại và kết quả kiểm chứng tương thích; phạm vi Cuckoo module được mô tả đúng.
- [x] R05: Mapping trong mọi tài liệu liên quan thống nhất với taxonomy có phiên bản; phân biệt attempt và execution bằng evidence.
- [x] R06: Có paired samples, split chống leakage, các baseline và định nghĩa attack success cho mục tiêu đã chọn.
- [x] R07: Evidence hỗ trợ transform provenance, multi/no-mapping và liên kết final report; policy vocabularies có quan hệ rõ ràng.
- [x] R08: Các mục tiêu có workload/hardware/batch/concurrency/percentile và cách tính tương ứng; schema compliance và abstention được đo riêng.
- [x] Kết quả kiểm tra lại được ghi nhận; trạng thái issue trước và các tuyên bố trong intent/spec phản ánh đúng mức độ đã kiểm chứng.

**Điều kiện cho bước tiếp theo:** chỉ tạo `agents.md` sau khi xác nhận các tiêu chí trên đã được đáp ứng. Việc viết hướng dẫn agent không thay thế việc giải quyết mâu thuẫn trong spec.

---

## 7. Tái kiểm tra T00 (2026-09-19)

- **Audit v1** (spec v1.3.0): 8/8 R-item PARTIAL → gate BLOCK (executor + supervisor; `reports/phase0-gate.json` v1).
- **Fix D01–D18** áp vào spec **v1.4.0** + `docs/adr/0002`/`0003`, `links.md`, intent v1.2.1, fixture metadata, `reports/integration-pin.json`.
- **Tái kiểm tra v2** (spec v1.4.0): 4 re-auditor + supervisor + verifier độc lập → **8/8 CLOSED, gate PASS** (`reports/phase0-gate.json` v2).
- Checklist §6 đã tick theo bằng chứng; Phase 2 được phép khởi động.
