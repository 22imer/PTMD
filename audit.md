# Audit định hướng — Guardrail cho agent phân tích mã độc

**Ngày:** 2026-09-21  
**Baseline:** `INTENT-RES-AI-2026-01` v1.2.1 và `SPEC-SEC-AI-2026-01` v1.4.0.  
**Phạm vi:** đối chiếu intent sơ khởi, baseline được phê duyệt, kiến trúc/code và bằng chứng hiện có trong working tree; không chỉ xét commit HEAD. Đây là audit định hướng và mức hoàn thành, không phải chứng nhận an toàn hay rà soát toàn bộ lỗi bảo mật.

## 1. Kết luận

**Repo vẫn đi đúng hướng về bài toán và kiến trúc, nhưng chưa hoàn thành mục tiêu nghiên cứu và chưa đủ điều kiện nghiệm thu full pipeline.**

- Đối tượng bảo vệ vẫn là **agent phân tích mã độc trước Indirect Prompt Injection**, không chuyển thành antivirus, hệ thống remediation hay agent điều khiển sandbox.
- Hai nhánh detection/capability, Tag-as-Evidence, Passive Consumer Agent và output governance đều có hiện thực prototype. Việc chuyển từ khảo sát sang prototype đã có căn cứ trong baseline/spec và gate Phase 0, không phải tự ý vi phạm ràng buộc “không viết code” của intent đã SUPERSEDED.
- Khoảng cách chính không phải thiếu thêm framework: **một số đường dữ liệu/contract còn lệch, model và nhánh động chưa nghiệm thu, chưa có dataset/agent thật/benchmark để trả lời giả thuyết**.
- `[INFERENCE]` Nguy cơ lệch hướng hiện nay là dừng ở “code + test + tài liệu đã nhiều” rồi coi đó là hiệu quả phòng thủ. Việc cần làm tiếp là khép các lỗi ảnh hưởng phép đo và tạo bằng chứng thực nghiệm, không mở rộng sản phẩm.

| Trục đánh giá | Kết luận | Mức bằng chứng |
|---|---|---|
| Bài toán, đối tượng bảo vệ, phạm vi Windows PE | Đúng hướng baseline | Intent §1.2/§1.3; spec §1.2; API nhận artifact/report |
| Kiến trúc và ranh giới quyền | Đúng hướng ở prototype | Code tách context, dispatcher allowlist, policy/evidence; chưa chứng minh triển khai cô lập của agent thật |
| Phủ hết detection và truy nguyên evidence | Chưa đầy đủ | A02–A04 bên dưới; không thể suy full static+dynamic từ API scanner tồn tại |
| Hiệu quả, latency, chất lượng phân tích nền | Chưa trả lời | Thiếu artifacts thực nghiệm; `SimulatedAgent` và số liệu synthetic không thay benchmark |
| Hồ sơ kế hoạch/nghiệm thu | Có drift trạng thái | A06; cập nhật PLAN/AGENTS trong đợt này, giữ nguyên trạng thái issue mở |

## 2. “Định hướng ban đầu” được hiểu theo nguồn nào?

### 2.1 Chuỗi nguồn và thay đổi có căn cứ

1. [`intent/pre-validate.md`](intent/pre-validate.md): ý tưởng ban đầu là tiền xử lý dữ liệu trước agent, dùng YARA/CAPEv2/CAPA/ML, phát hiện dấu vết và giữ evidence/mapping (dòng 6–19). Tài liệu tự ghi **SUPERSEDED** (dòng 1–4); “chưa code” là ràng buộc đợt khảo sát đó (dòng 21–29), không phải cấm mọi prototype về sau.
2. [`intent/research_pre_validate.md`](intent/research_pre_validate.md): baseline v1.2.1, câu hỏi trung tâm là mức giảm tấn công IPI **cùng chi phí độ trễ và suy giảm chất lượng phân tích** (§1.2, dòng 27–29). Bảng §1.3 (dòng 31–39) đã ghi rõ mở rộng sang đa tầng/dynamic và thu hẹp vào Windows PE.
3. [`specs/guardrail_malware_agent_spec.md`](specs/guardrail_malware_agent_spec.md): nguồn chuẩn cho contract; §7 yêu cầu prototype và benchmark; §6 định nghĩa paired design, bốn baseline, workload và metric. Trạng thái vẫn là **Draft — Pending Empirical Validation**.
4. [`reports/phase0-gate.json`](reports/phase0-gate.json): `gate=PASS`, 8/8 CLOSED ngày 2026-09-19 (dòng 13–14). Đây là gate làm rõ spec để mở build, không phải chứng cứ model chạy được hoặc target nghiên cứu đã đạt.

**Không tính là lệch hướng:** tách CAPA khỏi CAPEv2 (ADR-0001), Tag-as-Evidence thay dừng phân tích mặc định (ADR-0002), Passive Consumer Agent (ADR-0003), dùng `jsonschema` thay Guardrails AI trong prototype theo ngoại lệ có ghi nhận (ADR-0004). Các thay đổi này có quyết định và giữ mục tiêu bảo vệ agent; không được diễn giải thành đã tích hợp framework chưa dùng.

### 2.2 Bất biến còn được giữ trong đường code đã đọc

| Bất biến | Bằng chứng primary trong repo | Giới hạn kết luận |
|---|---|---|
| Chuỗi trích xuất đi normalization/detector; capability đi nhánh riêng | `src/guardrail/pipeline.py:609-679,837-843` | Nhánh static chưa tới ML; không coi hai nguồn là đã xác thực cùng mẫu |
| System instructions tách khỏi dữ liệu untrusted | `src/guardrail/context.py:316-376` — dựng hai message và gọi invariant check | Serialization không vô hiệu hóa ngữ nghĩa; không suy an toàn tuyệt đối |
| Dispatcher chỉ chấp nhận ba tool, kết quả qua ingress | `src/guardrail/runtime.py:198-238` — kiểm allowlist trước handler | Đây là contract dispatcher, không phải sandbox hệ điều hành cho callable agent bất kỳ |
| Mất backend không trở thành kết luận âm tính sạch | `src/guardrail/pipeline.py:735-748`; smoke §5 | Không có phép đo neural thật trong smoke |
| Fallback abstain thay ép BENIGN | `src/guardrail/report.py:275-333`; spec §3.6 | Fallback còn thiếu finding dương trong report (A03) |

## 3. Các khoảng cách ảnh hưởng trực tiếp định hướng

Ưu tiên dưới đây là ưu tiên **để chuẩn bị nghiệm thu nghiên cứu**, không đổi severity hay trạng thái của issue gốc.

### A01 — Chặn nghiệm thu: chưa có bằng chứng cho giả thuyết nghiên cứu

**Nguồn yêu cầu:** intent §1.2; spec §6.1–§6.7.

- Kiểm inventory trong phiên này: chưa có `reports/prompt_guard_measurements.json`, `reports/dataset_manifest.json`, `reports/split_manifest.json`, `reports/evaluation_results.json`, `reports/evaluation_summary.md`.
- Artifacts hiện có là `reports/evaluation_results.synthetic-example.json` và `reports/evaluation_summary.synthetic-example.md`; summary tự cảnh báo synthetic ở dòng 3–8.
- Agent mặc định là `SimulatedAgent`, nhận trực tiếp capabilities/evidence/policy outcome (`src/guardrail/pipeline.py:906-918`); verdict của nó không đo phản ứng một LLM trước Promptware.
- Tooling T10 là **bộ tính từ outcomes**, chưa phải runner bốn baseline: `src/guardrail/evaluation/metrics.py:3-6,1095-1117` nhận `SampleOutcome` theo tên baseline; `run_pipeline` không có profile bật/tắt các tầng (`pipeline.py:545-566`). Trong tooling đã kiểm chưa có đường chạy bốn cấu hình và chuyển kết quả/timing thật thành outcomes; cấp dataset/model thôi chưa đủ.
- `reports/environment.json:3-4,19-39` là manifest T01 cho contract test, không phải run manifest đầy đủ cho model/YARA/agent/hardware benchmark. `reports/integration-pin.json:4-18,34-36` ghi phiên bản/build **tham chiếu**, không chứng minh build Cuckoo đó đã được dùng.

**Tác động:** chưa thể trả lời mức giảm attack success, FPR trên Malware Commands, overhead hay chất lượng phân tích nền. Không có căn cứ kết luận target đạt; cũng chưa có căn cứ kết luận phương pháp thất bại.

**Cần đóng:** model/agent và môi trường có provenance thật, dataset được duyệt, bốn baseline trên cùng test split, raw outcomes/timings + denominators và kết luận pass/fail. Agent thật phải được nối **trước** phép đo.

### A02 — Lệch triển khai: detection thực tế hẹp hơn nhánh trong spec

**Nguồn yêu cầu:** spec §2, §3.4, §3.5.1.1; issue 2026-09-20 **SP-05/SP-06**.

- Static strings được normalize và quét YARA (`src/guardrail/pipeline.py:670-679`), nhưng lời gọi ML chỉ nhận `telemetry_normalized[:prompt_guard_budget]` (dòng 764–770).
- Việc cắt danh sách theo `prompt_guard_budget` không tự ghi phần bị bỏ vào coverage; coverage sau đó chỉ nhận kết quả phần đã đưa vào service (dòng 800–807).
- Thiếu quyền model và lỗi routing là hai vấn đề khác nhau: tải được weight không nối static strings vào ML hoặc khôi phục coverage bị mất.
- **Rủi ro bổ sung từ đọc tĩnh:** dedupe YARA giữ một finding/provenance cho mỗi rule (`pipeline.py:273-290`), nhưng `InstructionOverrideContext` lại đối chiếu từng provenance với danh sách đã dedupe (dòng 752–769). `[INFERENCE]` Với nhiều chuỗi cùng khớp một rule, chuỗi sau có thể mất corroboration cho predicate ML. Chưa repro runtime trong audit; cần kiểm tương tác này khi khép provenance/routing, không chỉ sửa trường hợp text trùng.

**Tác động:** không được gọi đường hiện tại là full neural coverage cho cả PE strings và telemetry; phép đo sẽ lệch phạm vi thiết kế nếu giữ nguyên.

**Cần đóng:** chốt budget chung/phân bổ, xử lý cả nguồn static/telemetry với provenance tương ứng, ghi `PARTIAL` khi cắt bỏ. Giữ predicate phân biệt Malware Command/Promptware; SP-02 đã được đóng trong issue, không mở lại chỉ vì SP-05 còn tồn tại.

### A03 — Ưu tiên sửa trước benchmark: coverage và tính toàn vẹn report/evidence

**Nguồn yêu cầu:** intent §3 mục 4–5; spec §3.5–§4; issue 2026-09-19 **L01–L05/L07**, issue 2026-09-20 **SP-03**.

| Khoảng cách còn mở | Bằng chứng | Liên hệ mục tiêu |
|---|---|---|
| L01: ingestion `PARTIAL` không vào coverage tổng | `pipeline.py:609-645,805-808` | Không được coi phần dữ liệu chưa xử lý là COMPLETE |
| L02: validator không nhận expected artifact hash/cờ bắt buộc | `report.py:177-221`; wiring `pipeline.py:920-922` | Schema hợp lệ chưa đảm bảo báo cáo đúng mẫu và đúng trạng thái rủi ro |
| L03: fallback luôn ghi không phát hiện injection, attempts rỗng | `report.py:314-317`; caller `pipeline.py:848-860,925-937` | Finding có thể còn trong danh sách evidence nhưng không được phản ánh trung thực trong report |
| L04/L05: telemetry thiếu trần byte từng chuỗi; provenance trùng không thống nhất | `README.md` §7 mục 4–5; `pipeline.py:622-625` | Budget và truy nguyên là điều kiện để số liệu đo có ý nghĩa |
| SP-03: chưa hiện thực kho raw evidence độc lập/truy hồi bằng hash | `evidence.py:486-503` chỉ nhận con trỏ; `pipeline.py:824-834`; issue SP-03 | Metadata evidence không thay nội dung gốc phục vụ kiểm tra lại |
| L07: chỉ kiểm định dạng hash, chưa binding CAPE/CAPA/bytes cùng mẫu | `pipeline.py:604-607`; `README.md:124` và §7 mục 7 | Trộn nguồn khác mẫu có thể làm sai cả kết luận và ground truth |

**Cần đóng:** ưu tiên L01–L05, sau đó đường ML, raw evidence và binding cùng-mẫu như `PLAN.md` §7. Không sửa spec để hợp thức hóa thiếu sót. Issue cũ có tên đề xuất như `POSITIVE`/`TRUNCATED_ARTIFACT_WARNING`; dùng enum chuẩn **`DETECTED`/`TRUNCATED_ARTIFACT_FLAG`** của spec khi triển khai.

### A04 — Chặn tích hợp: phần dynamic và model chưa đạt phạm vi ban đầu

**Nguồn yêu cầu:** intent §1.1/§3; spec §2–§3.4; `reports/build-report.md` §5.

- Memory-only Promptware là một lý do chính của kiến trúc đa tầng, nhưng extraction hiện loại memory dump khỏi phạm vi và không suy VA từ file offset (`src/guardrail/extraction.py:17-20`). Scanner API không thay đường ingest `VIRTUAL_ADDRESS` xuyên `run_pipeline`; SP-10/W-1 còn mở.
- Adapter chỉ trích sáu API A/W; `network.http/dns` thuộc đường Cuckoo riêng, không được adapter thay thế (`README.md` §4.2/§4.4). Build Cuckoo hiện unavailable theo ledger; không có chứng cứ happy-path thật cho nhánh này.
- **Rủi ro bổ sung từ đọc tĩnh:** finding Cuckoo được tạo với `provenance=None` (`yara_scanner.py:454-464`), trong khi pipeline ghi `has_provenance=True` và chuyển nguyên provenance sang evidence (`pipeline.py:253-269,713-731`); builder từ chối provenance không phải object (`evidence.py:211-213,379-382`). `[INFERENCE]` Khi có Cuckoo finding dương đi tới phát hành evidence, đường này có thể raise thay vì trả kết quả hợp lệ. Chưa repro trên build có Cuckoo; vì vậy điều kiện gỡ chặn phải kiểm **positive report → evidence E2E**, không chỉ module import/scan.
- Model ghim vẫn blocked; model thay thế nạp riêng được không phải tích hợp Lớp 3.

| Model / revision | Bằng chứng đang có, kế thừa hồ sơ ngày 2026-09-21 | Chưa chứng minh |
|---|---|---|
| `meta-llama/Prompt-Guard-86M` @ `1209add6ca7d9c1d815171b8e5571587fe3e7b03` | Pin trong `reports/integration-pin.json`; 403 chờ duyệt trong build-report §5 | Nạp weight, inference/latency và E2E thật |
| `meta-llama/Llama-Prompt-Guard-2-86M` @ `a8ded8e697ce7c355e395a0df51f94adb4a2fd27` | README §7 mục 8 ghi đã tải/nạp offline; `model.safetensors` sha256 `e72017dbbe89c1232dcbc4a74ce0c389db5b468c42afd05850347b2a8c5f6b09`, ngày 2026-09-21 | Tương thích label contract, calibration ngưỡng và nối pipeline; PG2 hai lớp không phải drop-in |

**Phân loại:** thiếu quyền model/build/lab là blocker môi trường; thiếu wiring memory/ML là khoảng cách code. Waiver Phase 2 không xóa phạm vi static+dynamic. Audit này không thử lại 403, không tải/nạp model và không chạy/unpack sample. Nếu đổi model, cần quyết định có ADR/spec + source + pin + calibration; không thay tên model âm thầm.

### A05 — Câu hỏi nghiên cứu rộng hơn các con số của harness

**Nguồn yêu cầu:** intent §6 câu 3–4 (dòng 160–161): hiệu quả giảm bề mặt tấn công nhờ CAPA và thông tin giữ được bởi Tag-as-Evidence so với dừng phân tích.

Bốn baseline bắt buộc của spec §6.3 và metric §6.6–§6.7 đánh giá toàn pipeline. Chúng không tự tách được đóng góp nhân quả riêng của CAPA hoặc định lượng thông tin giữ lại bởi Tag-as-Evidence. `[INFERENCE]` Ngay cả khi full pipeline đạt SLA, vẫn không thể suy hai kết quả riêng này chỉ từ chênh lệch full-vs-raw.

**Cần đóng:** giữ hai câu hỏi trong danh sách chưa trả lời; chốt phép đo/đối chứng nếu muốn đưa ra claim riêng. Không tự thêm baseline bắt buộc ngoài bốn cấu hình của spec trong đợt này; không để thiết kế ablation mới trì hoãn việc hoàn thành benchmark đã cam kết. Baseline Malware Accuracy và omission vẫn phải báo để không bỏ mất mục tiêu chất lượng phân tích nền.

**Khoảng cách protocol cần xử lý trước đo:** `metrics.py:738-739` đếm `encoded/decoded` từ cờ caller khai báo, chưa tự đối chiếu plaintext/transform và giới hạn depth/byte/printable của spec §6.6 (F-R2). Validator invariance kiểm giá trị Jaccard đã khai (`dataset_protocol.py:391-418`), không thay bằng chứng hành vi do lab cung cấp. `dataset_protocol.py:136-137,767-775` còn cưỡng chế cân bằng benign/malware 40/40 và 60/60 trong từng split, điều không được §6.2 yêu cầu (SP-08). Các điểm này là backlog code/protocol, không chỉ blocker môi trường; giữ outcome có nguồn và split đúng spec trước khi tính hiệu quả.

### A06 — Drift tài liệu làm mờ mức hoàn thành

**Bằng chứng tại thời điểm bắt đầu audit:**

- `PLAN.md` ghi `Draft — Plan Phase`, Phase 0 checkbox chưa tick và trạng thái dưới ngưỡng còn “chờ T00”, trong khi gate đã PASS và prototype đã tồn tại. **Đã cập nhật trong đợt này**, giữ Module/section đang dùng, thêm backlog và gate §7.
- `AGENTS.md` dễ bị đọc thành T01–T08 hoàn tất trọn vẹn. **Đã làm rõ** verdict lịch sử khác nghiệm thu tích hợp/empirical; bổ sung pointer audit và thứ tự chuẩn bị benchmark.
- `implemention.md:27-38` vẫn chứa ràng buộc của đợt chỉ viết tài liệu và câu “gate chưa xác nhận pass”, trong khi dòng 71 và checklist T00 đã PASS. T02/T04/T05 có checkbox nạp model/memory/Cuckoo đã tick (dòng 119,148–149,161), nhưng ledger ghi chưa có bằng chứng tương ứng; T08 dòng 206 nhắc Guardrails AI trong khi ADR-0004 hoãn framework. **Chưa sửa file này trong đợt audit**; cần đối soát trạng thái, không hiểu tick là đã chạy thật.
- `reports/build-report.md` §2 ghi `486 passed, 1 skipped` dưới nhãn “final” của wave cũ; issue 2026-09-20 §8 và README ghi baseline mới `494 passed, 2 skipped`. Đây là snapshot khác thời điểm, không phải hai kết quả của audit hiện tại.
- `graphify-out/graph.json` dùng tra cứu dẫn đường, không làm nguồn chuẩn: truy vấn phiên này còn trả node spec v1.1.0 trong khi tài liệu hiện hành v1.4.0. Các file lab ngoài git cũng không thay baseline.

**Cần đóng:** dùng `PLAN.md` §7 làm thứ tự hành động; giữ lịch sử wave, bổ sung thời điểm/phạm vi claim thay vì xóa lịch sử. Không tick nghiệm thu hệ thống khi chỉ có protocol, fixture hoặc waiver. Audit không đổi trạng thái kỹ thuật của model/môi trường và không đóng các issue trên.

## 4. Quyết định cho bước tiếp theo

Thứ tự và điều kiện hoàn thành chi tiết nằm ở [`PLAN.md` §7](PLAN.md#7-backlog-sau-audit-định-hướng-2026-09-21):

1. Khép L01–L05; sau đó static → ML/budget, raw evidence và binding cùng-mẫu.
2. Song song chuẩn bị model có quyết định rõ ràng, Cuckoo và memory artifact từ lab; không chạy sample trong repo.
3. Duyệt dataset/split, chốt môi trường và nối **agent thật + bốn đường chạy baseline trước khi đo**.
4. Chỉ mở benchmark nghiệm thu khi đủ gate; ghi raw outcomes/timings, tử số/mẫu số, failure/abstention và target pass/fail.
5. Trả lời câu hỏi nghiên cứu bằng kết quả, hoặc ghi rõ chưa trả lời. Chưa mở UI/server/production hay đổi sang bài toán khác.

## 5. Kiểm chứng trong phiên audit

### Đã thực hiện

- Đọc intent gốc/baseline, spec v1.4.0, glossary, ADR, gate, task checklist, ledger và issue; kiểm các đoạn code về routing, coverage, report và dispatcher được dẫn ở trên.
- Kiểm sự tồn tại của năm artifact empirical ở A01: **cả năm chưa có**.
- Chạy nguyên đoạn Python quickstart của `README.md` §3 bằng `.venv/bin/python`, `PYTHONPATH=src`, `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`; không đặt biến xuất JSON, không ghi đè fixture/artifact. Bytes demo tổng hợp tại chỗ, không phải Malware Sample.

Kết quả smoke (exit code **0**):

```text
processing_state=COMPLETE
detection_state=INCONCLUSIVE
pipeline_action=CAUTIOUS_QUARANTINE
META_PROMPT_GUARD: positive=False, errored=True
capabilities=5; evidence=2
agent_invoked=True; report_status=COMPLETE; verdict=MALICIOUS; attempts=1
executive_summary bắt đầu bằng "Simulated agent:"
```

**Diễn giải:** smoke xác nhận prototype offline đi hết đường demo và giữ trạng thái không kết luận được khi thiếu ML. `COMPLETE` là trạng thái xử lý của demo, không phải toàn hệ thống đã hoàn tất; verdict `MALICIOUS` là heuristic của agent mô phỏng. Fixture CAPE/CAPA demo khác nguồn và không chứng minh binding cùng-mẫu (`README.md` §3).

### Không thực hiện / không suy diễn

- Không sửa code/spec/issue, không chạy sample, không nạp model, không benchmark, không thay đổi môi trường hoặc commit.
- Không chạy lại full pytest/pyright: thay đổi là tài liệu; `494 passed, 2 skipped` và `276 errors, 2 warnings` là baseline **kế thừa hồ sơ**, không phải số đo của phiên này.
- Không tái xác minh nguồn học thuật hay từng mã taxonomy ngoài repo; audit này kiểm alignment với baseline, không xác nhận độc lập mọi khẳng định khoa học trong spec.
- Không chứng nhận toàn bộ code không có lỗi; các finding trên tập trung vào khoảng cách ảnh hưởng mục tiêu ban đầu, có tái sử dụng issue đã mở thay vì tạo verdict mới từ test count.

## 6. Phạm vi cập nhật và bài học

- Tạo `audit.md`: kết luận, traceability, khoảng cách và giới hạn kiểm chứng.
- Cập nhật `PLAN.md`: trạng thái thực, Phase 0 checkbox, trạng thái từng module, đủ metric và gate/backlog trước benchmark.
- Cập nhật `AGENTS.md`: cách đọc mức bằng chứng, nguồn audit và ưu tiên công việc, giữ ràng buộc an toàn.
- Ghi bài học append-only ở `memory/lessons-learned.md`: verdict wave/checkbox không thay bằng chứng runtime hoặc empirical.

**Lessons:** audit định hướng phải trả lời “có còn giải đúng bài toán không?” và “đã có bằng chứng nào?” riêng biệt. Prototype đúng hướng vẫn có thể chưa hoàn tất, và gate thiết kế đã PASS vẫn có thể cùng tồn tại với benchmark bị chặn.
