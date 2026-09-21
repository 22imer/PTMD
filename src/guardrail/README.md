# `src/guardrail/` — Prototype Guardrail cho Malware Analysis Agent

Prototype Phase 2 (spec v1.4.0, `implemention.md` T01–T10): dữ liệu mã độc (strings, telemetry, tool result) không bao giờ tự biến thành chỉ thị cho Agent; promptware được giữ làm bằng chứng (ADR-0002) và Agent chỉ là Passive Consumer (ADR-0003).

Cài đặt, quickstart, tham số `run_pipeline`, lệnh test/coverage và known limitations toàn repo là canonical ở [`README.md`](../../README.md) §1–§7; ở đây chỉ giữ phần riêng của package.

## Mục tiêu thiết kế

- Chuẩn hoá (Lớp 0) **trước** detector; mọi chuỗi giữ provenance + transform chain.
- Hai nhánh độc lập: Detection (YARA + Prompt Guard) và Capability (CAPA projection),
  hội tụ ở Decision Policy Gate — policy không tự suy luận score, không ép hai enum bằng nhau.
- Chỉ metadata/evidence summary đã được duyệt vào context; raw evidence ở kho điều tra.
- Output validate theo `schemas/final_report.schema.json`, re-ask hữu hạn (≤2), hết lượt thì
  abstain — **không bao giờ ép `BENIGN`**. Mọi tuyên bố hiệu quả là mục tiêu cần đo.

## Module map

| Module | Vai trò |
|---|---|
| `contracts.py` | Enum/TypedDict dùng chung, khớp hai schema trong `schemas/` (§4.1, §4.2). |
| `extraction.py` | Trích chuỗi tĩnh từ bytes: ASCII/UTF-16LE, locator/coverage theo budget (§3.2.1). |
| `telemetry.py` | Telemetry Ingestion Adapter: API arguments allowlist từ CAPEv2 report (§3.2.2). |
| `normalization.py` | Lớp 0: zero-width/NFKD/confusables, Base64/Hex depth ≤2, budget 64KB byte (§3.1). |
| `yara_scanner.py` | Lớp 1: YARA static/memory/Cuckoo; coverage COMPLETE/PARTIAL/FAILED tường minh. |
| `prompt_guard.py` | Lớp 3: Meta Prompt Guard-86M, ngưỡng 0.75, revision đọc từ `reports/integration-pin.json`. |
| `capa_projection.py` | Nhánh Capability: allowlist 4 khóa `tactic`/`technique_id`/`technique_name`/`namespace` (§3.3). |
| `policy.py` | Decision Policy Gate: ma trận 9 trạng thái + tổng hợp detector (§3.5.1, §3.5.1.1). |
| `evidence.py` | Bản ghi Quarantined Evidence (§4.1) cho finding/coverage gap/escalation/canary/dispatcher. |
| `context.py` | Lớp 4 (spotlighting): tách kênh system/untrusted, escape dữ liệu (§3.5.2). |
| `runtime.py` | Lớp 5: Read-Only Dispatcher, ingress filter, Canary Verifier (§3.6). |
| `report.py` | Output governance: validate §4.2, re-ask ≤2, fallback `ABSTAINED_PARTIAL`. |
| `pipeline.py` | E2E wiring Module 4: hai nhánh → gate → context → report trên một CAPEv2 report. |
| `evaluation/` | Package Phase 3: `dataset_protocol.py` (T09), `metrics.py` (T10). |

## Luồng dữ liệu (wiring hiện tại)

- **Động:** `TelemetryIngestionAdapter.ingest()` → Lớp 0 → YARA `scan_normalized` → Prompt Guard,
  nhưng chỉ nhận `telemetry_normalized[:prompt_guard_budget]` (`backend=None` ⇒ `errored` ⇒ `INCONCLUSIVE`).
- **Tĩnh:** `extract_strings(artifact_bytes)` → Lớp 0 → YARA `scan_normalized`; nhánh static **chưa**
  nối vào Prompt Guard (SP-05).
- **Capability:** `project_capabilities(capa_report)`, độc lập hai nhánh trên. **Cuckoo:** chỉ chạy khi
  caller truyền `cape_report_path`; build local thiếu `--enable-cuckoo` ⇒ `cuckoo_unavailable` + `PARTIAL`.
- **Hội tụ:** policy gate → evidence emission → context spotlighting → execution rails (dispatcher 3 tool
  read-only) → agent → report (validate / re-ask ≤2 / fallback) → Canary Token Verifier.

Thứ tự tầng bắt buộc: **extraction → normalization → detectors → policy → evidence → context → report**;
tool result của Agent quay lại đúng ingress policy. Định tuyến theo từng nguồn dữ liệu: `README.md` §4.

## Test seams

- `PromptGuardBackend` là `Protocol` (`prompt_guard.py`): test bơm stub tất định — `StubPromptGuardBackend`
  (`tests/test_pipeline.py`, `tests/test_e2e_adversarial.py`), `FakeBackend`/`FakeClock` (`tests/test_prompt_guard.py`).
- `run_pipeline(..., backend=None)` ⇒ detector `META_PROMPT_GUARD` ghi `errored` ⇒ `INCONCLUSIVE`.
- `agent_stub=` nhận callable theo `AgentRequest`; mặc định `SimulatedAgent` (xem WARNING bên dưới).
- `scanner=` cho phép bơm `YaraScanner` lỗi để chạm nhánh coverage `PARTIAL`/`FAILED`.
- `dispatcher_store=`, `canaries=`, `prompt_guard_config=`, `prompt_guard_budget=` cho các nhánh Lớp 5.
- Fixture `tests/fixtures/`: CAPE `cape_report_sample_harmless.json`/`cape_report_sample_edge_cases.json`, CAPA `cape_report_sample_harmless.json`/`capa_rd_real_small.json`, `dataset_manifest_example.json`, `atlas_snapshot_subset.json`. Smoke model thật là opt-in (`GUARDRAIL_PROMPT_GUARD_SMOKE=1`) và hiện **chưa chạy được** (xem bên dưới).

Chạy test/coverage/type-check: dùng đúng lệnh ở `README.md` §6.

## Artifacts

| Đường dẫn | Nội dung |
|---|---|
| `schemas/` | `quarantined_evidence.schema.json` (§4.1), `final_report.schema.json` (§4.2) — Draft-07. |
| `rules/` | `promptware.yar` (tĩnh, luôn biên dịch được), `promptware_cuckoo.yar` (cần module Cuckoo). |
| `reports/` | `phase0-gate.json`, `integration-pin.json`, `environment.json`, `coverage.json`, `evaluation_{results,summary}.synthetic-example.*` (số liệu tổng hợp, **không** phải benchmark). |

## Known blocked (ảnh hưởng trực tiếp package này)

- **Prompt Guard gated:** model pin `meta-llama/Prompt-Guard-86M` @ `1209add6…7b03` (spec §3.4) trả **403** (kiểm 2026-09-21) ⇒ chưa từng nạp weight thật, `reports/prompt_guard_measurements.json` chưa tồn tại; smoke ghim cứng `load_pin()` nên **không** đổi model chỉ bằng biến môi trường.
- **Model thay thế:** `meta-llama/Llama-Prompt-Guard-2-86M` @ `a8ded8e6…2fd27` nạp offline được nhưng không drop-in (2 lớp, không `id2label` ngữ nghĩa) ⇒ `resolve_label_mapping` ném `PromptGuardLabelMappingError`; ngưỡng `0.75` chưa hiệu chỉnh cho PG2.
- **Cuckoo + Phase 3:** `probe_cuckoo_capability()` → `available=False` (cờ `cuckoo_unavailable`) và `scan_cape_report` → `PARTIAL` + `ScanError(CAPABILITY)`, không fallback ngầm; T09/T10 thiếu `reports/{dataset,split}_manifest.json` + `reports/evaluation_results.json` ⇒ protocol/harness đã có, phép đo chưa chạy.

Chi tiết blocker, waiver và điều kiện gỡ: `reports/build-report.md` §5, `README.md` §7 mục 6/8.

## WARNING — `SimulatedAgent` chỉ dành cho dev/test

`run_pipeline` mặc định dùng `SimulatedAgent`: nó nhận sẵn policy outcome + evidence và suy
verdict theo heuristic (`MALICIOUS` khi có capability, ngược lại `SUSPICIOUS`; `BENIGN` chỉ khi
không có evidence). **Không dùng cho evaluation thật** và không được coi verdict mô phỏng là
hành vi agent (spec §6.4 đo hành vi agent thật). Evaluation phải truyền `agent_stub=` là agent
thật; `executive_summary` của run mô phỏng đã ghi rõ nhãn "Simulated agent".
