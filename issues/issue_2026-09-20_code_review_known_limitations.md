# Code Review — Xác minh 7 giới hạn kỹ thuật L01–L07 (Known Limitations)

- **Ngày:** 2026-09-20
- **Trạng thái:** Completed — Review / Verification
- **Ưu tiên:** P1
- **Loại:** Code Review / Independent Verification
- **Đối tượng review:** `issues/issue_2026-09-19_readme_known_limitations.md` (Open / Proposed, untracked)
- **Mã nguồn đã kiểm:** `src/guardrail/{pipeline,report,telemetry,normalization,extraction,policy,contracts,yara_scanner}.py`
- **Baseline:** `master` HEAD `2352648` (prototype Phase 2, spec v1.4.0)
- **Tài liệu tham chiếu:** `specs/guardrail_malware_agent_spec.md` v1.4.0 (§3.2.2, §3.5.1, §3.5.1.1, §3.6, §4.2), `reports/build-report.md`, `docs/adr/0002-tag-as-evidence-over-hard-block.md`

---

## 1. Mục tiêu & Phương pháp

Issue `issue_2026-09-19_readme_known_limitations.md` đề xuất sửa 7 giới hạn L01–L07. Review này **kiểm chứng độc lập** từng tuyên bố trên code hiện hành (không chạy sample/binary; chỉ đọc code + dựng dữ liệu trong bộ nhớ), xác định đúng/sai, mức nghiêm trọng thực tế và phân loại (defect vs hardening vs waiver).

Bằng chứng tái lập:

```bash
# Baseline (khớp build-report §2)
.venv/bin/python -m pytest -q            # 486 passed, 1 skipped

# Kịch bản xác minh trong bộ nhớ (không chạm mẫu)
.venv/bin/python /tmp/opencode/verify_limitations.py
.venv/bin/python /tmp/opencode/verify_l03.py
```

Kết quả chạy được trích nguyên văn ở từng mục dưới đây.

---

## 2. Ma trận verdict

| ID | Tuyên bố của issue | Verdict | Mức độ thực tế | Có phải vi phạm spec? |
|---|---|---|---|---|
| **L01** | `ingestion.coverage` rơi khỏi `processing_state` | **CONFIRMED** | P1 High | **Có** — §3.2.2 + §3.5.1 hàng 4–6 |
| **L02** | Validator không đối chiếu SHA256 / `status_flags` | **CONFIRMED** | P2 (hardening) | **Không** — §3.6 chỉ định nghĩa phạm vi validate là schema + tham chiếu evidence |
| **L03** | `build_fallback_report` che giấu phát hiện dương | **CONFIRMED** | P1 | **Một phần** — Finding Preservation Rule vẫn đạt ở tầng evidence; report *field* sai lệch |
| **L04** | Telemetry không giới hạn trần độ dài chuỗi đơn | **CONFIRMED**, tác động lớn hơn issue mô tả | P2 | Không (ngoài MUST, nhưng §3.2.1 chặn 256 ký tự cho nhánh tĩnh) |
| **L05** | Bất nhất thứ tự provenance + log mâu thuẫn code | **CONFIRMED** | P3 (Low) — không ảnh hưởng an ninh | Không |
| **L06** | Ràng buộc môi trường Phase 3 | **CONFIRMED** — mô tả chính xác | N/A (Group B) | Không — waiver, không phải defect code |
| **L07** | Thiếu đối chiếu cùng-mẫu SHA256 giữa các nguồn | **CONFIRMED** (vắng mặt) | P3 (Advisory) | **Không** — không có MUST trong spec |

Tổng: 7/7 tuyên bố đều đúng về mặt hiện tượng. **3 mục là defect thực sự** (L01, L03, và phần log/hành vi của L05); **L02/L07 là hardening** (issue xếp P1 hơi quá tay so với spec); **L04** đúng và bị đánh giá *thấp hơn* thực tế; **L06** là waiver hợp lệ.

---

## 3. Xác minh chi tiết

### L01 — [P1, CONFIRMED] Ingestion `PARTIAL` rơi khỏi coverage tổng

- **Vị trí:** `src/guardrail/pipeline.py:575-580`, `604`, `750`. `TelemetryIngestionAdapter.ingest()` chỉ trả `COMPLETE`/`PARTIAL` (`telemetry.py:152-157`).
- **Kết quả chạy thật:**

  ```text
  L01 ingestion.coverage = PARTIAL | errors = 1 | strings = 0
  L01 processing_state = COMPLETE | detection_state = INCONCLUSIVE
  L01 action = CAUTIOUS_QUARANTINE | flags = ['DETECTOR_DISAGREEMENT']
  ```

- **Phân tích:** `ingestion.coverage` chỉ được đưa vào *thông điệp* `limitations` (`pipeline.py:576-580`), không được `append` vào danh sách `coverage` (dòng 597–604). Khi telemetry lỗi cấu trúc nhưng `telemetry_scan` `COMPLETE`, `_coverage_states` trả `COMPLETE`. Hệ quả: hàng ma trận bị tra sai — đáng lẽ `PARTIAL + INCONCLUSIVE` (hàng 6: `ESCALATE_AND_INCONCLUSIVE` + `TRUNCATED_ARTIFACT_FLAG` + `DETECTOR_DISAGREEMENT`, **P1 chặn verdict**) nhưng thực tế ra `COMPLETE + INCONCLUSIVE` (hàng 3: `CAUTIOUS_QUARANTINE`, chỉ `DETECTOR_DISAGREEMENT`, P2). **Thiếu cờ `TRUNCATED_ARTIFACT_FLAG` và hạ escalation.**
- **Vi phạm spec:** §3.2.2 ("report thiếu trường bắt buộc ⇒ lỗi schema và processing state `PARTIAL`") và §3.5.1 hàng 4–6.
- **Test gap:** test `PARTIAL` hiện có (`tests/test_pipeline.py:322-348`) bơm coverage qua `PartialCoverageScanner` (scanner), **không** đi qua đường `ingestion.errors`. Nhánh của L01 chưa được test.
- **Đính chính nhỏ:** issue gọi adapter trả `PARTIAL` đúng, nhưng tuyên bố `telemetry_errored` kiểm `ingestion.coverage is FAILED` (dòng 608) — xem thêm **A1**.

### L02 — [CONFIRMED, spec không bắt buộc] Validator bỏ qua SHA256 và `status_flags`

- **Vị trí:** `src/guardrail/report.py:177-221`.
- **Kết quả chạy thật:**

  ```text
  L02 validate_final_report(wrong sha, no status_flags).valid = True | errors = []
  L02 params = ['report', 'evidence_store', 'banned_verdicts', 'schema']
  ```

- **Phân tích:** report mang `sha256 = "b"*64` (khác artifact) và **không** có `status_flags` vẫn `valid=True`. Hàm không có tham số `expected_sha256`/`required_status_flags`; schema chỉ ràng buộc *pattern* 64 hex (`schemas/final_report.schema.json:30-33`) chứ không so khớp artifact.
- **Đối chiếu spec:** §3.6 chỉ liệt kê 3 nghĩa vụ validate: JSON Schema, tham chiếu `evidence_id`, và fallback abstention. **Không** có MUST về so khớp hash/`status_flags`. Do đó đây là **hardening/defense-in-depth**, không phải lỗi vi phạm spec. Mức thực tế đề xuất **P2**, thấp hơn P1 mà issue gán.
- **Đính chính:** L02 viết cờ là `TRUNCATED_ARTIFACT_WARNING`; tên đúng trong vocabulary là **`TRUNCATED_ARTIFACT_FLAG`** (`contracts.py:132`, schema enum dòng 99–102).

### L03 — [P1, CONFIRMED có nuance] Fallback che giấu phát hiện dương

- **Vị trí:** `src/guardrail/report.py:314-317`.
- **Kết quả chạy thật** (kịch bản đúng hàng 7: `FAILED + DETECTED`, `forward_to_agent=False`):

  ```text
  processing = FAILED
  detection  = DETECTED
  action     = PIPELINE_ABSTENTION | forward = False
  evidence   = 2 records
  report.adversarial_evasion_findings = {'prompt_injection_detected': False, 'evasion_attempts': []}
  evidence contains a positive finding?: True
  ```

- **Phân tích:** fallback hardcode `prompt_injection_detected=False` và `evasion_attempts=[]` bất kể `detection_state`. Bằng chứng dương vẫn được phát hành thành bản ghi evidence (đúng Finding Preservation Rule §3.5.1 dòng 329), nhưng **báo cáo người dùng đọc lại tuyên bố không phát hiện injection** → sai lệch thông tin.
- **Nuance quan trọng:** đây **không** phải vi phạm Finding Preservation Rule ở tầng evidence (finding vẫn nằm trong `PipelineResult.evidence`); vấn đề là trường report không phản ánh detection. Bản thân module đã có logic "bảo toàn cờ dương" ở nhánh khác — `_merge_canary_findings` đặt `prompt_injection_detected: True` (`pipeline.py:985`), chứng tỏ ý định thiết kế là cờ phải true khi có dương. Vậy L03 là **bất nhất nội tại**, không chỉ là thiếu sót.
- **Đính chính:** issue dùng `detection_state == POSITIVE`; vocabulary đúng là **`DetectionState.DETECTED`**. Ngoài hàng 7, hàng 9 (`FAILED + INCONCLUSIVE`) và mọi nhánh fallback do re-ask/canary cũng dính cùng hành vi.

### L04 — [P2, CONFIRMED — nặng hơn mô tả] Không trần độ dài telemetry

- **Vị trí:** `src/guardrail/telemetry.py:140-157`, `291-340`; so sánh `extraction.py:53-54` (`MAX_STRING_LENGTH = 256`).
- **Kết quả chạy thật:**

  ```text
  L04 accepted single-string length = 2000005 | extraction MAX_STRING_LENGTH = 256
  L04 normalized length = 2000005 (processed fully, no 64KB gate on raw input)
  ```

- **Phân tích & mở rộng:** adapter chỉ có cận dưới (`len >= 6`) và lọc tiền tố `0x`; không có cận trên. Quan trọng hơn tuyên bố của issue: ngân sách 64KB của Normalization (`normalization.py:56`, dòng 151–154) **chỉ chặn bước decode**, không chặn đầu vào thô — `unicodedata.normalize("NFKD", text)` và vòng homoglyph (`normalization.py:136-145`) vẫn chạy full trên toàn bộ chuỗi, và `_decode_nul_interleaved` (`telemetry.py:324`) cũng chạy trên full chuỗi trước khi bất kỳ ngân sách nào áp dụng. Do đó rủi ro cạn kiệt tài nguyên **lớn hơn** issue mô tả, và "budget 64KB bảo vệ" là giả định sai.
- **Đối chiếu spec:** §3.2.2 không nêu trần độ dài cho adapter, nhưng §3.2.1 chặn tĩnh ở 256 ký tự ⇒ bất đối xứng rõ. Đề xuất giải pháp của issue (thêm `MAX_STRING_LEN` + truncate/ghi lỗi) là hợp lý.

### L05 — [P3, CONFIRMED] Bất nhất provenance + log mâu thuẫn hành vi

- **Vị trí:** `pipeline.py:587-591` (dict comprehension giữ bản ghi **cuối**) so với thông điệp dòng 590 ("bản ghi **đầu tiên** giữ provenance") và `_dedupe_yara_findings` (`pipeline.py:272-289`, giữ bản ghi **đầu**).
- **Kết quả chạy thật:**

  ```text
  L05 retained locator = /last | pipeline message says: first record keeps provenance
  ```

- **Phân tích:** đúng như issue nêu. Đây là lỗi **tính nhất quán/tài liệu hóa**, không có tác động an ninh trực tiếp (cả hai bản ghi đều là provenance hợp lệ của cùng một text). Mức thực tế **P3 (Low)**, thấp hơn P2 issue gán.
- **Nuance:** tiểu tuyên bố 4 của issue ("provenance giữa nhánh tĩnh và nhánh động không có cơ chế hợp nhất liên nhánh") **yếu** — mỗi `Finding` mang provenance riêng từ nhánh sinh ra nó, không cần "hợp nhất"; không nên gộp tiểu mục này vào cùng mức với 3 tiểu mục còn lại.

### L06 — [CONFIRMED — waiver hợp lệ, không phải defect]

- **Phân tích:** mô tả chính xác so với `reports/build-report.md` §5 và `src/guardrail/README.md` (model gated 401, thiếu `--enable-cuckoo`, chưa có `reports/prompt_guard_measurements.json` / `dataset_manifest.json`). Không có `reports/prompt_guard_measurements.json` trong `reports/` — đúng. Đây là ràng buộc môi trường, issue tự phân loại Group B chuẩn.

### L07 — [P3, CONFIRMED — vắng mặt, nhưng không spec bắt buộc]

- **Vị trí:** `run_pipeline` chỉ regex-hóa `artifact_sha256` (`pipeline.py:569-572`).
- **Kết quả chạy thật:**

  ```text
  L07 pipeline ran with mismatched bytes/hash -> processing = COMPLETE (no SOURCE_ARTIFACT_MISMATCH)
  ```

- **Phân tích:** đúng là không có bất kỳ đối chiếu chéo nào (bytes ↔ CAPE target ↔ CAPA metadata). Tuy nhiên spec §4/§3.6 không có MUST về cross-source hash consistency ⇒ đây là **enhancement** để tích hợp hệ thống lớn, **P3 Advisory**, thấp hơn P1/P2 của issue.
- **Lưu ý thực tế:** fixture CAPE harmless có `target.file.sha256 = "0"*64` (`tests/fixtures/cape_report_sample_harmless.json`) trùng `SHA256 = "0"*64` trong test, nên có thể bật cho CAPE; nhưng `artifact_bytes` không được test nào truyền (xem A3) và CAPA report fixture (`capa_report_sample_harmless.json`) **không có trường hash** (`fixture_metadata`/`meta`/`rules`) ⇒ đối chiếu với CAPA metadata là bất khả thi ở dạng fixture hiện tại. Giải pháp cần `allow_synthetic_mismatch` hoặc hash thật là hợp lý.

---

## 4. Phát hiện bổ sung ngoài issue (mới trong review này)

| ID | Mức | Vị trí | Nội dung | Đề xuất |
|---|---|---|---|---|
| **A1** | P2 | `pipeline.py:607-610` | `telemetry_errored = ingestion.coverage is ProcessingState.FAILED or ...`: adapter **không bao giờ** trả `FAILED` (`telemetry.py:152-157` chỉ `COMPLETE`/`PARTIAL`) ⇒ nhánh đầu là **dead check**; telemetry lỗi cấu trúc không đánh dấu detector `errored`. Cùng gốc với L01 nhưng ở lớp detector-flag. | Sửa thành `is not ProcessingState.COMPLETE` (hoặc xử lý cùng fix L01). |
| **A2** | P2 | `normalization.py:136-145`, `telemetry.py:324` | Ngân sách 64KB **chỉ gate decode**, không gate NFKD/homoglyph/NUL-decode trên đầu vào thô ⇒ L04 tác động thật lớn hơn mô tả. | Áp trần độ dài ở `telemetry`/`extraction` trước Normalization; ghi coverage `PARTIAL` như §3.2.1. |
| **A3** | P2 | `pipeline.py:636-697`; `tests/` | Nhánh E2E `artifact_bytes` (static/`YARA_STATIC`) và `cape_report_path` (`YARA_CUCKOO`) **không có test nào** đi qua `run_pipeline` (grep `artifact_bytes`/`cape_report_path` trong `tests/` = 0 match). Build-report xếp T08 PASS cho tích hợp nhưng hai nhánh tuỳ chọn này chưa được phủ ở tầng pipeline. | Bổ sung test pipeline cho 2 nhánh (đây cũng là điều kiện để sửa L07 an toàn). |
| **A4** | P2 | `report.py:294-333` | `build_fallback_report` **không chứa bất kỳ `evidence_id` nào** ⇒ report fallback không thể tham chiếu bằng chứng dương, và `validate_final_report` chấp nhận (không có evidence ref nào để kiểm). Kể cả khi sửa L03 ở mức boolean, report vẫn không liên kết được finding. | Quyết định thiết kế: fallback có nên phát hành `evasion_attempts` với `evidence_id` (Finding Preservation ở tầng report) hay không; nếu có, validator cần kiểm. |

---

## 5. Đính chính đối với issue gốc

1. **L02:** `TRUNCATED_ARTIFACT_WARNING` → **`TRUNCATED_ARTIFACT_FLAG`** (`contracts.py:132`).
2. **L03:** `detection_state == POSITIVE` → **`DetectionState.DETECTED`**; và hành vi fallback cũng đúng cho hàng 9 và các nhánh re-ask/canary, không chỉ hàng 7.
3. **L02/L07:** cần phân loại là **hardening/defense-in-depth** (không có MUST trong §3.6), thay vì ngang hàng P1 với L01/L03.
4. **L04:** mô tả cần nâng cấp — "budget 64KB ở Normalization" **không** bảo vệ đầu vào thô (xem A2).
5. **L05:** tiểu tuyên bố "hợp nhất provenance liên nhánh" không phải defect; tách khỏi 3 tiểu mục còn lại.

---

## 6. Khuyến nghị xử lý

- **Chấp nhận issue là Open** với các đính chính §5; giữ nguyên L01, L03 ở P1; hạ L02/L05/L07 xuống mức tương ứng (P2/P3/P3).
- **Hợp nhất L01 + A1** thành một fix duy nhất (đưa `ingestion.coverage` vào tổng hợp `processing_state` **và** sửa `telemetry_errored`), kèm regression test bơm lỗi cấu trúc qua telemetry (không dùng scanner stub) khẳng định `processing_state is PARTIAL` + `TRUNCATED_ARTIFACT_FLAG`.
- **L03 + A4**: sửa `build_fallback_report` nhận `detection_state`/`findings` và phát hành `evasion_attempts` có `evidence_id`; regression test cho hàng 7 (`FAILED + DETECTED`) và cho fallback re-ask.
- **L04 + A2**: chốt trần độ dài đơn vị ở pha trích xuất (telemetry) và ghi `PARTIAL` khi truncate; test property với chuỗi cực lớn.
- **A3**: bổ sung test E2E cho `artifact_bytes` và `cape_report_path` trước khi làm L07.
- **L06**: giữ waiver; nhắc lại khuyến nghị build-report §6 (smoke Prompt Guard, dataset, 4 baseline) là điều kiện Phase 3, không phải phạm vi review này.
- Sau khi sửa, cập nhật `README.md` §7 / `reports/build-report.md` §5 theo trạng thái thực (đúng AC-07 của issue).

---

## 7. Tổng kết

Review độc lập xác nhận **cả 7 tuyên bố L01–L07 đều có thật trên code hiện hành**; không có tuyên bố nào sai về hiện tượng. Tuy nhiên issue **đánh giá quá cao** L02/L07 (không phải vi phạm spec) và **đánh giá thấp** L04 (ngân sách 64KB không bảo vệ đầu vào thô). Ba defect cần ưu tiên là **L01 (hàng ma trận sai + thiếu cờ), L03 (report che giấu dương), và A1 (dead check cùng gốc L01)**. Baseline suite tái lập đúng: `486 passed, 1 skipped`.
