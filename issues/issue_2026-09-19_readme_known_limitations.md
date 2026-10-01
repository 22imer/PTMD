# Kế hoạch và đặc tả khắc phục 7 giới hạn kỹ thuật đã ghi nhận trong README (Known Limitations)

- **Ngày:** 2026-09-19
- **Trạng thái:** Open / Proposed
- **Ưu tiên:** P1
- **Loại:** Bug / Data Integrity / Security Architecture / Validation / Operational Readiness
- **Tài liệu tham chiếu:** `README.md` §7, `reports/build-report.md` §5, `specs/guardrail_malware_agent_spec.md` v1.4.0, `CONTEXT.md`
- **Mã nguồn liên quan:**
  - `src/guardrail/pipeline.py`
  - `src/guardrail/report.py`
  - `src/guardrail/telemetry.py`
  - `src/guardrail/extraction.py`
  - `schemas/final_report.schema.json`
  - `tests/fixtures/cape_report_sample_harmless.json`

---

## 1. Bối cảnh và Mục tiêu

Tại thời điểm kết thúc Phase 2 prototype (commit `aa43183`, Spec v1.4.0), hệ thống đã hoàn thành việc kiểm chứng tích hợp E2E và đóng toàn bộ các wave T00–T10. Tuy nhiên, qua quá trình kiểm thử độc lập và nghiệm thu, mục 7 của `README.md` cùng mục 5 của `reports/build-report.md` đã ghi nhận công khai **7 giới hạn kỹ thuật tồn đọng (Known Limitations)**.

Mục tiêu của issue này là:
1. Định danh chi tiết bản chất kỹ thuật, vị trí mã nguồn, và rủi ro của từng điểm trong số 7 giới hạn.
2. Phân loại ranh giới trách nhiệm:
   - **Nhóm A (Khắc phục trong Prototype Phase 2):** Các lỗi logic xử lý dữ liệu, kiểm tra schema/hash, và tính toàn vẹn thông tin (L01, L02, L03, L04, L05).
   - **Nhóm B (Chuyển giao và Ràng buộc Môi trường Phase 3):** Các giới hạn phụ thuộc vào tài nguyên môi trường ngoài repo (tải model Prompt Guard bị gated, build YARA Cuckoo, dataset benchmark đối kháng thật) (L06, L07).
3. Đề xuất giải pháp sửa đổi cụ thể và tiêu chí nghiệm thu (Acceptance Criteria) cho từng mục.

---

## 2. Ma trận tổng hợp 7 giới hạn kỹ thuật

| ID | Vấn đề ghi nhận | Mức độ | Phạm vi ảnh hưởng | Phân loại |
|---|---|---|---|---|
| **L01** | Ingestion `PARTIAL` bị rơi khỏi coverage tổng tại pipeline | **P1 (High)** | `pipeline.py:575–604, 750` | Logic / Policy Gate |
| **L02** | Validator report không đối chiếu `artifact_sha256` và thiếu cưỡng chế `status_flags` | **P1 (High)** | `report.py:177–221`, `pipeline.py:815–835` | Governance / Output Validation |
| **L03** | `build_fallback_report` che giấu phát hiện dương (`prompt_injection_detected=False`) | **P1 (High)** | `report.py:314–317`, `pipeline.py:840–860` | Information Integrity / Reporting |
| **L04** | Telemetry Ingestion không giới hạn trần độ dài byte cho từng chuỗi đơn lẻ | **P2 (Medium)** | `telemetry.py:140–230` | DoS Resistance / Resource Exhaustion |
| **L05** | Bất nhất trong thứ tự lưu trữ provenance đối với các chuỗi trùng lặp | **P2 (Medium)** | `pipeline.py:587–591, 272–289` | Data Provenance Traceability |
| **L06** | Chưa có số liệu đo thực nghiệm (Prompt Guard 86M 401, YARA Cuckoo, Dataset) | **P2 (Medium)** | `reports/build-report.md` §5, `evaluation/` | Environment & Empirical Waiver |
| **L07** | Thiếu cơ chế đối chiếu cùng-mẫu giữa các nguồn dữ liệu độc lập (CAPE / CAPA / Bytes) | **P2 (Medium)** | `pipeline.py:518–572`, fixtures | Ingestion Contract / Forensic Binding |

---

## 3. Chi tiết kỹ thuật và Phương án khắc phục

### L01 — [P1] Ingestion `PARTIAL` bị rơi khỏi coverage tổng tại `run_pipeline`

- **Vị trí mã nguồn:** `src/guardrail/pipeline.py:575–604`, `750`.
- **Hiện tượng:**
  Tại `pipeline.py:575`, `ingestion = TelemetryIngestionAdapter().ingest(cape_report)` trả về `ingestion.coverage` (có thể là `PARTIAL` nếu có lỗi cấu trúc JSON Pointer hoặc telemetry vượt quá 2.000 chuỗi).
  Tuy nhiên, tại `pipeline.py:597–604`, danh sách `coverage` chỉ thu thập:
  ```python
  telemetry_scan = scanner.scan_normalized(telemetry_normalized, ...)
  coverage.append(telemetry_scan.coverage)
  ```
  `ingestion.coverage` hoàn toàn không được `append` vào danh sách `coverage`.
  Đến `pipeline.py:750`:
  ```python
  processing_state = _coverage_states(coverage) if coverage else ProcessingState.FAILED
  ```
  Nếu các chuỗi trích xuất được quét YARA thành công (`telemetry_scan.coverage == COMPLETE`), `processing_state` sẽ được đánh giá là `COMPLETE` ngay cả khi dữ liệu telemetry bị lỗi cấu trúc nặng hoặc bị cắt cụt (truncated).
- **Rủi ro:** Vi phạm spec §3.5.1. Khi telemetry bị truncate hoặc có lỗi cấu trúc, trạng thái hệ thống phải là `PARTIAL` để áp dụng hình phạt tự tin (`confidence_penalty`) và gắn cờ cảnh báo `TRUNCATED_ARTIFACT_WARNING`. Việc rơi mất trạng thái khiến hệ thống đưa ra quyết định sai trong policy gate.
- **Phương án khắc phục:**
  1. Thêm `coverage.append(ingestion.coverage)` vào danh sách tổng hợp coverage tại `pipeline.py`.
  2. Bổ sung test case: Khi `cape_report` chứa lỗi cấu trúc hoặc vượt quá trần chuỗi khiến `ingestion.coverage == PARTIAL`, `PipelineResult.processing_state` bắt buộc phải là `PARTIAL`.

---

### L02 — [P1] `validate_final_report` không đối chiếu SHA256 và thiếu cưỡng chế `status_flags`

- **Vị trí mã nguồn:** `src/guardrail/report.py:177–221`, `src/guardrail/pipeline.py:815–835`.
- **Hiện tượng:**
  1. `validate_final_report` chỉ kiểm tra tính hợp lệ về mặt cú pháp schema (chuỗi 64 ký tự hex qua `_schema_errors`), nhưng không nhận tham số `expected_sha256` và không đối chiếu `report["sample_metadata"]["sha256"] == artifact_sha256`. Nếu Agent trả về SHA256 của một sample khác hoặc hash giả lập, validator vẫn chấp nhận `valid=True`.
  2. Validator không kiểm tra tính bắt buộc của `status_flags` tương ứng với ô ma trận đã kích hoạt trong Policy Gate (spec §3.5.1). Ví dụ: khi `processing_state == PARTIAL`, spec bắt buộc phải có cờ `TRUNCATED_ARTIFACT_WARNING`, nhưng validator hiện tại không cưỡng chế điều này.
- **Rủi ro:** Agent có thể hallucinate thông tin định danh mẫu độc hoặc bỏ qua các cờ cảnh báo rủi ro mà không bị chặn lại ở Output Governance.
- **Phương án khắc phục:**
  1. Mở rộng chữ ký `validate_final_report` và `ReportValidator`: bổ sung `expected_sha256: str | None = None` và `required_status_flags: Iterable[str] = ()`.
  2. Kiểm tra `report["sample_metadata"]["sha256"] == expected_sha256`.
  3. Kiểm tra mọi cờ trong `required_status_flags` đều phải có mặt trong `report["status_flags"]`.
  4. Cập nhật `run_pipeline` truyền đúng `artifact_sha256` và `outcome.add_flag` vào validator.

---

### L03 — [P1] `build_fallback_report` che giấu phát hiện dương (`prompt_injection_detected=False`)

- **Vị trí mã nguồn:** `src/guardrail/report.py:314–317`.
- **Hiện tượng:**
  Hàm `build_fallback_report` luôn thiết lập cố định:
  ```python
  "adversarial_evasion_findings": {
      "prompt_injection_detected": False,
      "evasion_attempts": [],
  },
  ```
  Nếu hệ thống phát hiện tấn công Injection (`detection_state == POSITIVE`), nhưng quá trình xử lý rơi vào fallback (ví dụ do `processing_state == FAILED` hoặc Agent sinh báo cáo lỗi quá số lần `max_re_asks`), fallback report được sinh ra lại thông báo là không phát hiện thấy injection. Bằng chứng dương tính chỉ nằm trong kho `evidence` mà biến mất khỏi bản báo cáo phân tích cho người dùng.
- **Rủi ro:** Đánh lừa chuyên viên phân tích đọc báo cáo cuối, vi phạm nguyên tắc toàn vẹn thông tin và mục tiêu minh bạch bằng chứng đối kháng của kiến trúc Tag-as-Evidence (ADR-0002).
- **Phương án khắc phục:**
  1. Bổ sung tham số `detection_state: DetectionState` và `findings: Sequence[EvidenceFinding] = ()` (hoặc `evidence_store`) vào `build_fallback_report`.
  2. Khi `detection_state == DetectionState.POSITIVE`, điền `prompt_injection_detected=True` và ánh xạ danh sách các kỹ thuật/chuỗi phát hiện được vào `evasion_attempts`.
  3. Cập nhật `run_pipeline` khi gọi `build_fallback_report` phải truyền đúng trạng thái phát hiện đã có.

---

### L04 — [P2] Telemetry Ingestion không giới hạn trần độ dài byte cho từng chuỗi đơn lẻ

- **Vị trí mã nguồn:** `src/guardrail/telemetry.py:140–230`.
- **Hiện tượng:**
  `TelemetryIngestionAdapter` có cấu hình `max_strings = 2000` và lọc bỏ các chuỗi có độ dài `< 6` ký tự hoặc bắt đầu bằng `0x`. Tuy nhiên, adapter hoàn toàn không đặt giới hạn trên (upper bound) cho độ dài ký tự hoặc dung lượng byte của một chuỗi đơn lẻ. Trong khi đó, nhánh static (`extraction.py:28–29`) giới hạn nghiêm ngặt `MAX_STRING_LEN = 256`.
- **Rủi ro:** Mã độc có thể cố tình gọi `OutputDebugStringA` hoặc `SetWindowTextA` với chuỗi payload khổng lồ (vài chục MB) trong sandbox. Khi parse log JSON, `telemetry.py` sẽ nạp toàn bộ chuỗi này vào bộ nhớ, gây lãng phí tài nguyên và rủi ro Denial of Service (DoS) bộ nhớ trước khi kịp đến bước Normalization (nơi có budget 64KB).
- **Phương án khắc phục:**
  1. Định nghĩa hằng số `MAX_STRING_LEN: int = 4096` (hoặc theo cấu hình phù hợp với API call) trong `telemetry.py`.
  2. Cắt tỉa (truncate) hoặc ghi lỗi cấu trúc đối với các chuỗi vượt quá giới hạn trên, đảm bảo không nhận chuỗi dài vô hạn vào pipeline.

---

### L05 — [P2] Bất nhất trong thứ tự lưu trữ provenance đối với các chuỗi trùng lặp

- **Vị trí mã nguồn:** `src/guardrail/pipeline.py:587–591`, `272–289`.
- **Hiện tượng:**
  1. Tại `pipeline.py:587`:
     ```python
     provenance_by_text = {item.normalized_string: item for item in telemetry_normalized}
     ```
     Khi một chuỗi xuất hiện nhiều lần với các provenance khác nhau trong telemetry, dict comprehension của Python sẽ để bản ghi **cuối cùng** ghi đè lên các bản ghi trước.
  2. Tuy nhiên, thông báo ghi nhận giới hạn ở dòng 590 lại viết:
     `"Có chuỗi telemetry trùng sau chuẩn hoá; bản ghi đầu tiên giữ provenance."`
     (Thông báo mâu thuẫn trực tiếp với hành vi thực tế của code).
  3. Trong khi đó, hàm gộp YARA findings `_dedupe_yara_findings` (`pipeline.py:272–289`) lại giữ lại bản ghi **đầu tiên** (`index = seen[key]`, chỉ cập nhật `transform_chain`).
  4. Hơn nữa, provenance giữa nhánh tĩnh (`artifact_bytes`) và nhánh động (`cape_report`) không có cơ chế hợp nhất liên nhánh.
- **Rủi ro:** Dẫn xuất nguồn gốc (data provenance) của bằng chứng không nhất quán giữa các detector, gây khó khăn cho việc đối soát pháp y và truy vết nguyên nhân gốc.
- **Phương án khắc phục:**
  1. Chuẩn hóa quy tắc: Giữ bản ghi đầu tiên (`first-seen`) một cách rõ ràng và nhất quán bằng cách kiểm tra `if text not in provenance_by_text: provenance_by_text[text] = item`.
  2. Cập nhật cấu trúc dữ liệu để có thể lưu trữ danh sách các vị trí xuất hiện (multi-occurrence provenance) nếu cần thiết, hoặc thống nhất cơ chế dedupe giữa YARA và Prompt Guard.

---

### L06 — [P2] Ràng buộc môi trường và đo đạc thực nghiệm Phase 3 (Prompt Guard 86M, Cuckoo, Dataset)

- **Vị trí mã nguồn:** `reports/build-report.md` §5, `src/guardrail/prompt_guard.py`, `rules/promptware_cuckoo.yar`.
- **Hiện tượng:**
  1. Model `meta-llama/Prompt-Guard-86M` là model gated trên HuggingFace (yêu cầu chấp thuận điều khoản và API token). Trong môi trường offline, `backend=None` khiến detector luôn ghi `errored=True` và rơi vào `INCONCLUSIVE`.
  2. Thư viện `yara-python` biên dịch mặc định không có cờ `--enable-cuckoo`, dẫn đến không thể kích hoạt `rules/promptware_cuckoo.yar`.
  3. Chưa thực hiện benchmark đo đạc trên 200 cặp mẫu thật; file `reports/evaluation_results.synthetic-example.json` chỉ là số liệu harness kiểm thử cấu trúc.
- **Phương án quản lý (Phase 3 Roadmap):**
  1. Duy trì trạng thái **Waiver có tuyên bố** đối với Phase 2 (như đã ghi trong ADR-0004 và `build-report.md`).
  2. Xây dựng quy trình CI/CD runner có cấu hình secret `HF_TOKEN` và YARA build flag cho Phase 3.
  3. Tuyệt đối không trích dẫn các file `*.synthetic-example.*` như là bằng chứng về hiệu quả phòng thủ trước khi có dataset thực nghiệm.

---

### L07 — [P2] Thiếu cơ chế đối chiếu cùng-mẫu giữa các nguồn dữ liệu độc lập

- **Vị trí mã nguồn:** `src/guardrail/pipeline.py:518–572`, `tests/fixtures/cape_report_sample_harmless.json`.
- **Hiện tượng:**
  Hàm `run_pipeline` nhận đồng thời `cape_report`, `capa_report`, `artifact_bytes` và `artifact_sha256`. Tuy nhiên:
  - Hàm chỉ kiểm tra regex định dạng của `artifact_sha256`.
  - Không so sánh `artifact_sha256` với `cape_report.get("target", {}).get("file", {}).get("sha256")`.
  - Không so sánh với hash trong metadata của `capa_report`.
  - Nếu truyền cả `artifact_bytes`, hàm không tự động kiểm tra `hashlib.sha256(artifact_bytes).hexdigest() == artifact_sha256`.
- **Rủi ro:** Khi tích hợp vào hệ thống lớn, caller có thể sơ suất truyền nhầm dữ liệu telemetry của mẫu A cùng với capability của mẫu B và bytes của mẫu C, dẫn đến việc phân tích râu ông nọ cắm cằm bà kia mà pipeline không hề cảnh báo.
- **Phương án khắc phục:**
  1. Bổ sung bước kiểm tra ràng buộc chéo (Cross-source Hash Consistency Check) trong `run_pipeline`.
  2. Nếu có sự bất đồng hash giữa các nguồn dữ liệu được cung cấp, trả về lỗi cấu trúc hoặc hạ trạng thái về `FAILED` với lý do `SOURCE_ARTIFACT_MISMATCH`.
  3. Cập nhật các fixture kiểm thử để đảm bảo tính nhất quán (hoặc đánh dấu cờ `allow_synthetic_mismatch=True` dành riêng cho unit test).

---

## 4. Kế hoạch triển khai và Phân công

### Đợt 1: Khắc phục nhóm lỗi logic nội tại (Prototype Hardening)
- **Mục tiêu:** Giải quyết dứt điểm **L01, L02, L03, L04, L05**.
- **Tệp chỉnh sửa:**
  - `src/guardrail/pipeline.py`
  - `src/guardrail/report.py`
  - `src/guardrail/telemetry.py`
  - `tests/test_pipeline.py`
  - `tests/test_report.py`
  - `tests/test_telemetry.py`
- **Yêu cầu an toàn:** Toàn bộ 486 test hiện có phải tiếp tục pass; bổ sung regression test cho từng lỗi được sửa; không làm suy giảm coverage.

### Đợt 2: Chuẩn bị điều kiện cho Phase 3 (Empirical & Integration Contracts)
- **Mục tiêu:** Xử lý **L07** (cross-check hash) và lập hồ sơ chuẩn bị môi trường cho **L06**.
- **Tệp chỉnh sửa / Bổ sung:**
  - Cập nhật fixture CAPE với hash thực tế hoặc cơ chế bypass có kiểm soát cho test.
  - Xây dựng tài liệu hướng dẫn setup môi trường phân tích thật (CAPEv2 lab + HuggingFace Token).

---

## 5. Tiêu chí nghiệm thu đóng Issue (Acceptance Criteria)

- [ ] **AC-01 (L01):** `ingestion.coverage` được đưa vào mảng tính toán `processing_state`. Test case chứng minh telemetry có lỗi cấu trúc khiến pipeline hạ xuống `PARTIAL`.
- [ ] **AC-02 (L02):** `validate_final_report` từ chối báo cáo nếu `sample_metadata.sha256` không khớp với artifact được phân tích hoặc thiếu cờ `status_flags` bắt buộc theo chính sách.
- [ ] **AC-03 (L03):** `build_fallback_report` giữ nguyên cờ `prompt_injection_detected=True` và danh sách bằng chứng khi `detection_state == POSITIVE`.
- [ ] **AC-04 (L04):** `telemetry.py` có giới hạn trần độ dài ký tự cho mỗi API call string, ngăn ngừa cạn kiệt bộ nhớ.
- [ ] **AC-05 (L05):** `pipeline.py` bảo toàn provenance của bản ghi đầu tiên (`first-seen`) một cách tất định, khớp với nội dung log cảnh báo.
- [ ] **AC-06 (L07):** `run_pipeline` kiểm tra sự đồng nhất SHA256 giữa các đầu vào dữ liệu (bytes, CAPE, CAPA) hoặc có cơ chế cảnh báo sai lệch nguồn.
- [ ] **AC-07:** Cập nhật mục 7 của `README.md` chuyển trạng thái các mục đã xử lý sang Resolved.
