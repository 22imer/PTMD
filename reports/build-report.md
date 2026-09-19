# Build Report — Guardrail Malware Agent (Phase 2, prototype)

**Ngày:** 2026-09-19 · **HEAD:** `aa43183` · **Spec:** SPEC-SEC-AI-2026-01 v1.4.0 · **Môi trường:** `reports/environment.json`
**Phạm vi:** tổng hợp wave build T01–T10 + hai wave hardening (L4a/L4b) + các fix wave; verdict supervisor theo mục;
bug ledger; phần bị chặn/waiver và định hướng Phase 3. Đây là báo cáo nghiệm thu **prototype correctness**, không phải
báo cáo hiệu quả thực nghiệm: §6.7 vẫn là target hypothesis chưa đo.

## 1. Waves & commits

| Wave / task | Nội dung | Commit | Verdict nguồn |
|---|---|---|---|
| T00 — gate Phase 0 | spec v1.3.0 → **v1.4.0** (D01–D18), ADR-0002/0003, `links.md`, `reports/phase0-gate.json`, `reports/integration-pin.json` | `ab51ed9` (khởi tạo chứa toàn bộ artifact T00) | PASS 8/8 CLOSED (`GateKeeper3`+`GateKeeper4`) |
| T01 — contracts/schema/môi trường | `contracts.py`, 2 schema Draft-07, `pyproject.toml`, `reports/environment.json`, `tests/test_contracts.py` | `ab51ed9` | PASS (`ContractWatch`, Mục B) |
| T02 — extraction + telemetry | `extraction.py`, `telemetry.py`, fixture CAPE vô hại/edge cases | `ab51ed9`; fix `98f7027` (W-2) | PASS (`DetectionWatch`; re-check `muc-c-sup`) |
| T03 — normalization | `normalization.py`, bảng confusables ghim | `ab51ed9`; fix B1 nằm trong `114501e` | PASS (`DetectionWatch`) |
| T04 — YARA scanner + ruleset | `yara_scanner.py`, `rules/promptware.yar`, `rules/promptware_cuckoo.yar` | `82bd76a`; fix B2 `141cf87` | PASS (`muc-c-sup` re-verify sau B2) |
| T05 — Prompt Guard service | `prompt_guard.py`, `tests/test_prompt_guard.py` (71 test) | `f954050` | PASS (`muc-c-sup`); đo inference thật blocked |
| T06 — CAPA allowlist projection | `capa_projection.py` + fixture tổng hợp/thật | `ab51ed9`; fix `a609dc2` + `5cb085d` | BLOCK → **PASS** (`CapabilityWatch` → `muc-d-sup`) |
| T07 — policy gate + evidence | `policy.py`, `evidence.py`, test ma trận 9 trạng thái | `cd93410` | PASS (`muc-e-sup`, 4/4 mutation bị giết) |
| T08 — context/rails/report + tích hợp | `context.py`, `runtime.py`, `report.py`, `pipeline.py`, `test_{context,runtime,report,pipeline}.py` | `7d1ce7a`; `6a9a644` (battery E2E); `aa43183` (R1/R2) | PASS with residuals (`muc-e-sup`, 5/5 mutation bị giết) |
| T09 — dataset protocol | `evaluation/dataset_protocol.py`, `tests/evaluation/test_dataset_protocol.py`, `dataset_manifest_example.json` | `a849474`; loop-2 `a5b1d01` | PASS tooling / empirical blocked (`muc-f-sup`) |
| T10 — metrics & reporting harness | `evaluation/metrics.py`, `tests/evaluation/test_metrics.py`, artifact `*.synthetic-example.*` | `1e0e38e`; loop-2 `a5b1d01` | PASS tooling / empirical blocked (`muc-f-sup`) |
| Hardening **L4a** | battery property/fuzz + coverage + determinism liên module/xuyên tiến trình + ép pin confusables + fix B1/W-2 | `114501e`, `98f7027`, `1f7004a`, `e0912fd` | PASS (`l4-verify`; 7/7 check, mutation có răng) |
| Hardening **L4b** | battery E2E đối kháng 10 scenario + fix B2 (lone surrogate) | `141cf87`, `6a9a644` | PASS (`muc-c-sup` B2 re-verify) |
| Fix wave T06 | bám khóa FIELD `attack` của capa thật thay alias `att&ck` | `a609dc2`, `5cb085d` | PASS (`muc-d-sup`, 2 tài liệu producer thật) |
| Fix wave T08 | sanitize mapping KEY của canary verifier + chặn needle rỗng (R1/R2) | `aa43183` (+7 test trong `tests/test_runtime.py`) | CLOSED (`muc-e-sup` R1/R2) |
| Chore | untrack `graphify-out/`, ignore pytest artifacts, memory ledger LL-013…LL-018 | `f1c65e1`, `87c4c38`, `41088c2`, `01191d1`, `c8ef40d`, `756afd9` | — |

Số test toàn suite theo mốc: `388 passed, 1 skipped` (Mục D) → `469 passed, 1 skipped` (`7d1ce7a`, `muc-e-sup`) →
`479 passed, 1 skipped` (sau battery L4b) → **`486 passed, 1 skipped`** (sau `aa43183`).

## 2. Kết quả test / coverage cuối

- **Full suite (final): `486 passed, 1 skipped in 3.80s`** (`.venv/bin/python -m pytest -q`; 487 collected).
  - Skip duy nhất: `tests/test_prompt_guard.py:563` — smoke model thật, opt-in `GUARDRAIL_PROMPT_GUARD_SMOKE=1`.
  - Cảnh báo còn lại: `DeprecationWarning: invalid escape sequence '\_'` từ docstring `evaluation/metrics.py`
    (residual F-R13, LOW; có từ `1e0e38e`, không phải lỗi hành vi).
- **Coverage nhóm L0–L3 rerun scoped** (`--cov=src/guardrail`, 178 passed): `contracts.py` 100% (100 stmts),
  `extraction.py` 100% (105), `telemetry.py` 100% (137), `capa_projection.py` 100% (102),
  `normalization.py` **97.33%** (75 stmts, thiếu dòng **182–183**).
  - Hai dòng 182–183 là nhánh `except` **không thể chạm**: `HEX_REGEX` bảo đảm hex độ dài chẵn nên
    `bytes.fromhex` không raise, và `decode(..., errors="ignore")` cũng không raise (đã kiểm độc lập).
  - `reports/coverage.json` (commit `1f7004a`) là snapshot của wave L4a cho nhóm file trên; các module giao sau
    (`policy/evidence/context/runtime/report/pipeline/prompt_guard/yara_scanner/evaluation`) **chưa có snapshot
    coverage đầy đủ** — không suy diễn con số coverage cho các module này.
- Test theo mục: T01 11 · T04 12 · T06 48 · T07 90 · T08 61 · T05 71 · evaluation 58 (29 protocol + 29 metrics) ·
  hardening L4a 55 · battery E2E L4b 10.

## 3. Supervisor verdict roster

| Mục | Supervisor | Verdict | Bằng chứng chốt |
|---|---|---|---|
| **A** — Gate Phase 0 (T00) | `GateKeeper3` + verifier `GateKeeper4` | **PASS** | 8/8 R-item CLOSED sau fix D01–D18; `reports/phase0-gate.json` |
| **B** — Contracts & môi trường (T01) | `ContractWatch` | **PASS** | schema ↔ spec bằng `json.loads` 100%; 10/10 tập enum khớp; 11/11 test; 4/4 mutation bị phát hiện; manifest khớp môi trường thật |
| **C** — Detection branch (T02–T05) | `DetectionWatch`, sau đó `muc-c-sup` | **PASS** | T02/T03 PASS độc lập (provenance, transform chain, budget, coverage); T04 PASS sau fix B2 (`muc-c-sup`: 22 passed scoped, 479 passed full, mutation revert tái hiện đúng `UnicodeEncodeError`); T05 PASS (71 test, ngưỡng 0.75/predicate/coverage) |
| **D** — Capability branch (T06) | `CapabilityWatch` → `muc-d-sup` | **PASS** (was BLOCK) | 48 passed; parse 2 tài liệu capa producer thật (215.811 B @7.0.1 + fixture re-emit 9.1.0) cho kết quả byte-identical với parser tay; 3 nhóm mutation bị giết; 494 needle free-text không rò |
| **E** — Policy & Integration (T07–T08) | `muc-e-sup` | **PASS with residuals** | T07: 9/9 hàng ma trận khớp đủ tuple, 4/4 mutation bị giết; T08: 5/5 mutation bị giết, E2E độc lập của supervisor tái lập mọi bất biến (payload 14.332 ký tự byte-identical 2 lần chạy) |
| **F** — Evaluation (T09–T10) | `muc-f-sup` (loop-2) | **PARTIAL** | Tooling PASS (`a849474`/`1e0e38e`/`a5b1d01`); empirical **blocked** — không có dataset/lab |

**Disposition residual của Mục E:** R1 (CanaryVerifier bỏ qua mapping KEY) và R2 (`_replace_case_insensitive` treo
với needle rỗng) → **đã fix trong `aa43183`** + test mới. R3 (smoke model thật) → **waiver tường minh** (xem §5).
R4 (chưa ghi nhận deferral Guardrails AI ngoài docstring) → **ADR-0004** + sửa docstring `report.py`. R5 (`SimulatedAgent`
là mặc định và được cấp policy outcome) → **note**: cảnh báo trong `src/guardrail/README.md`, không dùng cho evaluation.
R6 (thiếu `tests/test_report.py` trong danh sách T08) → đã bổ sung vào `implemention.md`. R7 (thay đổi của sibling
trong lúc audit) → đã xử lý bằng battery L4b + lần chạy full suite cuối.

**Disposition residual của Mục F:** loop-1 có 12 residual; `a5b1d01` đóng R1, R3–R10, R12 (mỗi closure được supervisor
reprobe độc lập; 58 test evaluation). Còn mở: **R2** (MEDIUM — manifest chưa có cờ encoding + harness chưa kiểm tiêu chí
depth/64KB/printable cho de-obfuscation), **R11** (LOW — nửa còn lại: `pair_id` không tồn tại trong rejection log vẫn
được chấp nhận), **R13** (LOW — DeprecationWarning docstring), **R14** (NIT), **R15** (LOW — join bỏ qua khi row thiếu
`sample_id`). Verdict mục vẫn PARTIAL vì tầng empirical chưa chạy được.

## 4. Bug ledger

| ID | Mô tả | Phát hiện bởi | Fix | Trạng thái |
|---|---|---|---|---|
| **B1** | `normalize` crash `UnicodeEncodeError` với lone surrogate (`\ud800` từ JSON escape trong report CAPE) | hardening L4a (fuzz/property) | `114501e` — budget đo bằng `encode("utf-8","surrogatepass")` | Đóng; mutation revert → test đỏ; byte semantics chuỗi hợp lệ không đổi |
| **W-2** | Chuỗi wide NUL-interleaved (`i\x00g\x00…`) lọt detector vì không được giải mã | hardening L4a | `98f7027` — `_decode_nul_interleaved` (chỉ nhận pattern NUL xen kẽ hợp lệ) | Đóng; negative control (WIDE/WIDEST/thường) giữ nguyên; test `test_telemetry.py` + `test_hardening.py` |
| **B2** | `YaraScanner` truyền `str` thẳng vào `rules.match` ⇒ lone surrogate làm `UnicodeEncodeError` thoát khỏi `run_pipeline` (DoS do input kiểm soát, pipeline im lặng) | hardening L4b (scenario 3) | `141cf87` — encode `surrogatepass` khi payload là `str`, bytes giữ nguyên | Đóng; regression `test_e2e_adversarial.py::test_nul_wide_and_lone_surrogate_values_never_silence_pipeline`; mutation revert tái hiện đúng lỗi |
| **capa `attack` key** | Parser bám alias `att&ck` trong khi capa 9.1.0 phát FIELD `attack` ⇒ mọi tài liệu thật cho **0 row giả** (fixture tự-xác-nhận không bắt được) | `CapabilityWatch` (Mục D) | `a609dc2` + `5cb085d`; fixture thật `tests/fixtures/capa_rd_real_small.json` | Đóng; `muc-d-sup` đối chiếu 2 tài liệu producer thật độc lập |
| **R1-keys** | `CanaryVerifier` chỉ quét value, bỏ qua mapping KEY ⇒ canary/system marker lọt qua dạng khóa (`verify({CANARY: 'v'}) → released=True`) | `muc-e-sup` (Mục E) | `aa43183` — sanitize key qua cùng đường `_sanitize_text` | Đóng; test trong `tests/test_runtime.py` |
| **R2-loop** | `_replace_case_insensitive('abc','')` treo vô hạn khi `system_markers` chứa chuỗi rỗng | `muc-e-sup` (Mục E) | `aa43183` — guard needle rỗng 2 lớp (constructor + hàm) | Đóng; test trong `tests/test_runtime.py` |

## 5. Blocked & waivers

| Mục | Trạng thái | Điều kiện gỡ |
|---|---|---|
| Meta Prompt Guard-86M gated (401) — không có `reports/prompt_guard_measurements.json`, chưa đo latency thật | **Waiver tường minh (E-R3, C-R-C2)**: blocker môi trường, không phải defect code; acceptance T05 vẫn ghi blocked, không phát sinh score giả | Chạy `GUARDRAIL_PROMPT_GUARD_SMOKE=1` với quyền HF, lưu kết quả thô vào `reports/` **trước mọi claim Phase 3** |
| Module Cuckoo không có trong build YARA local (yara-python 4.5.4, không `--enable-cuckoo`) | Degradation theo spec §3.2.2: `probe_cuckoo_capability()` → `available=False` + cờ `cuckoo_unavailable`; `scan_cape_report` → `ScanError(CAPABILITY)` + `coverage=PARTIAL`, không fallback ngầm | Dựng YARA có Cuckoo + chạy happy-path report import (residual C-R1) |
| Nhánh provenance memory dump (`VIRTUAL_ADDRESS`) chưa có runtime evidence | **Defer có tuyên bố** (spec §3.2.2 note, residual W-1): cần dump PE-sieve thật ở Phase 2; không coi là delivery defect của T02 | Lab cung cấp memory dump + metadata nguồn xác nhận |
| Benchmark thực nghiệm T09/T10 (dataset, split, 4 baseline, timing, §6.7 pass/fail) | **Blocked ngoài tầm executor**: thiếu `reports/{dataset,split}_manifest.json` và `reports/evaluation_results.json`; artifact hiện có là `*.synthetic-example.*` — số liệu harness, **không được trích dẫn như bằng chứng hiệu quả** | Duyệt dataset paired 200 pairs trong lab + chạy 4 baseline trên test split |
| Residual mở không waiver | F-R2 (MEDIUM), F-R11/F-R13/F-R15 (LOW), F-R14 (NIT), C-R-C4 (LOW — surrogate trong keyword là vấn đề Lớp 0, T04 báo NOT_DETECTED tường minh), D-low (INFO) | Xem `agent://muc-f-sup`, `agent://muc-c-sup`, `agent://muc-d-sup` |

## 6. Định hướng Phase 3 (ngắn)

1. **Gỡ chặn model**: chạy smoke Prompt Guard-86M theo revision đã ghim, đo latency thật (batch 8–16) → đóng E-R3/C-R2.
2. **Dataset**: duyệt paired dataset 200 pairs trong lab, xuất `dataset_manifest.json` + `split_manifest.json`;
   đóng F-R2 (cờ encoding + transform chain trong outcome), F-R11 (đối soát inventory), F-R15 (bắt buộc `sample_id`).
3. **Đo**: chạy 4 baseline trên test split, C=1/4/8, p95 @C=1, báo tử số/mẫu số + abstention; xuất
   `evaluation_results.json` + summary thật, từng target ghi pass/fail kèm cờ `SLA_MISSED` nếu không đạt.
4. **Agent thật**: thay `SimulatedAgent` bằng agent thật trong evaluation (verdict mô phỏng không phải hành vi agent);
   giữ nguyên bất biến passive consumer + 3 tool read-only.
5. **Kết luận**: chỉ đánh dấu nghiệm thu hệ thống khi tách rõ prototype correctness, empirical efficacy và residual risk.

**Kết luận prototype correctness:** T01–T08 đã hoàn tất end-to-end trên fixture vô hại với contract được supervisor
xác minh độc lập (ma trận 9 trạng thái, preservation rule, ingress/spotlighting, dispatcher read-only, canary,
validate/re-ask/abstain) và các bug B1/W-2/B2, capa `attack`, R1-keys, R2-loop đã đóng kèm regression test.
**Empirical efficacy chưa được chứng minh** — không có phép đo nào trên dataset thật; mọi mục tiêu §6.7 giữ nguyên
trạng thái target hypothesis, và các giới hạn ở §5 là phần chưa kiểm chứng được công bố.
