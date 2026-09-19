# Guardrail chống Indirect Prompt Injection cho agent phân tích mã độc

Prototype Phase 2 (spec `SPEC-SEC-AI-2026-01` v1.4.0) nhằm **giảm thiểu rủi ro** Indirect Prompt Injection: dữ liệu mã độc (strings, telemetry, tool result) không trở thành chỉ thị cho LLM Agent; promptware được giữ làm bằng chứng (ADR-0002) và agent chỉ tiêu thụ thụ động (ADR-0003). Đây là defense-in-depth, **không cam kết triệt tiêu** — residual risk vẫn còn (spec §1.1).

Trạng thái: **prototype, chưa production**; hiệu quả phòng thủ chưa được đo trên dataset thật (`reports/build-report.md` §5). Đọc `AGENTS.md` trước khi thao tác trong repo (không chạy sample, coi mọi byte là dữ liệu không tin cậy) và `CONTEXT.md` cho thuật ngữ.

## 1. Yêu cầu môi trường

- Python >= 3.11 (đã chạy: CPython 3.11.15 trên Linux/WSL2 — `reports/environment.json`); chạy offline, model thật là opt-in.
- Dependency thực tế (version đã kiểm trong `.venv` hiện có):

| Gói | Vai trò | Version |
|---|---|---|
| `jsonschema` | validate report Draft-07 | 4.26.0 |
| `yara-python` | bắt buộc khi import `guardrail.yara_scanner` (pipeline mặc định) | 4.5.4 |
| `pytest` | chạy test | 9.1.1 |
| `pytest-cov` | đo coverage khi cần (tuỳ chọn) | 7.1.0 |
| `transformers` + `torch` | chỉ khi dùng Prompt Guard thật (tuỳ chọn) | 5.17.0 / 2.14.0+cpu |

`yara-python` và `pytest-cov` không được khai báo trong `pyproject.toml` (chỉ `jsonschema` là dependency, `pytest` nằm ở extra `dev`), nên phải cài tay khi cần.

## 2. Cài đặt và chạy từ checkout

Tái sử dụng `.venv` sẵn có (khuyến nghị):

```bash
# Chạy từ thư mục gốc repo checkout
test -x .venv/bin/python && .venv/bin/python -V
PYTHONPATH=src .venv/bin/python -c "import jsonschema, yara, guardrail.pipeline; print('OK')"
```

Tạo môi trường mới chỉ khi chưa tồn tại (không cài gì vào `.venv` đang dùng):

```bash
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install "jsonschema==4.26.0" "yara-python==4.5.4" "pytest==9.1.1" "pytest-cov==7.1.0"
fi
```

Nếu `.venv` đã tồn tại nhưng thiếu gói, chỉ cài vào môi trường của chính bạn (ví dụ
`.venv/bin/python -m pip install "yara-python==4.5.4"`).

Không dùng `pip install .` như một cách chạy đủ: wheel cài được package `guardrail` (setuptools auto-discovery cho layout `src/`) nhưng **không kèm dữ liệu** — `rules/`, `schemas/`, `reports/integration-pin.json` và `src/guardrail/data/confusables_min.json` được resolve từ source tree (`Path(__file__).resolve().parents[2]`) nên thiếu trong wheel, và `yara-python` cũng không được khai báo. Luôn chạy với `PYTHONPATH=src` từ gốc checkout; `pytest` tự lấy `pythonpath = ["src"]` từ `pyproject.toml`.

## 3. Quickstart: chạy E2E trên fixture vô hại

Chạy đúng heredoc sau từ gốc checkout. Demo chỉ đọc fixture, không ghi đè fixture/artifact.

```bash
# Chạy từ thư mục gốc repo checkout
PYTHONPATH=src .venv/bin/python - <<'PY'
import hashlib, json, os, pathlib
from guardrail.pipeline import run_pipeline

root = pathlib.Path.cwd()
cape = json.loads((root / "tests/fixtures/cape_report_sample_harmless.json").read_text(encoding="utf-8"))
capa = json.loads((root / "tests/fixtures/capa_rd_real_small.json").read_text(encoding="utf-8"))

# Bytes tổng hợp tại chỗ — KHÔNG phải sample thật và không phải bytes của fixture CAPE.
# Vì có artifact_bytes, artifact_sha256 phải là sha256 của đúng bytes này.
artifact_bytes = b"MZ\x00\x00" + b"guardrail-demo-harmless\x00" + b"cmd.exe /c echo demo\r\n\x00"
artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()

result = run_pipeline(
    cape,
    artifact_sha256=artifact_sha256,   # hash của đúng artifact_bytes ở trên
    artifact_bytes=artifact_bytes,
    capa_report=capa,
    backend=None,                      # chưa có backend PG: khai báo rõ, không tự tải model
)

print("artifact_sha256 :", result.artifact_sha256)
print("state           :", result.processing_state, "| detection:", result.detection_state,
      "| action:", result.decision.pipeline_action, "| forward:", result.decision.forward_to_agent)
print("detectors       :", [(d["name"], d["positive"], d.get("errored", False))
                            for d in result.detector_results])
print("capabilities    :", len(result.capabilities), result.capabilities[:2])
print("evidence        :", len(result.evidence), "bản ghi quarantine")
print("agent_invoked   :", result.agent_invoked, "| report_status:", result.report_status,
      "| verdict:", result.verdict, "| attempts:", result.report_outcome.attempts)
for line in result.limitations:
    print("  limitation:", line)
print("executive_summary:", result.report["executive_summary"])

# Tuỳ chọn: xuất toàn bộ kết quả JSON (payload + evidence) ra đường dẫn bạn chọn.
if os.environ.get("GUARDRAIL_DEMO_JSON"):
    with open(os.environ["GUARDRAIL_DEMO_JSON"], "x", encoding="utf-8") as fh:
        fh.write(result.to_json())
    print("JSON:", os.environ["GUARDRAIL_DEMO_JSON"])
PY
```

Đầu ra rút gọn (tất định, đã chạy với `.venv` hiện có):

```text
artifact_sha256 : b92d9ac98df0976ac5d771b6d6788ea3809b3165ce325f58ae104bd11078202b
state           : COMPLETE | detection: INCONCLUSIVE | action: CAUTIOUS_QUARANTINE | forward: True
detectors       : [('TELEMETRY_ADAPTER', True, False), ('YARA_STATIC', False, False), ('META_PROMPT_GUARD', False, True)]
capabilities    : 5 [{'tactic': 'Defense Evasion', 'technique_id': 'T1140', ...}, …]
evidence        : 2 bản ghi quarantine
agent_invoked   : True | report_status: COMPLETE | verdict: MALICIOUS | attempts: 1
  limitation: Prompt Guard không có backend (model gated) — detector bắt buộc errored.
executive_summary: Simulated agent: 2 bản ghi đối kháng, 5 capability ATT&CK; kết luận MALICIOUS.
```

Đọc kết quả:

- `META_PROMPT_GUARD errored=True` vì `backend=None` (model gated) → detector bắt buộc lỗi → `detection_state=INCONCLUSIVE` → policy `CAUTIOUS_QUARANTINE`, **không** phải kết luận âm tính.
- Verdict `MALICIOUS` đến từ `SimulatedAgent` mặc định (heuristic: có capability ⇒ MALICIOUS); `executive_summary` tự ghi nhãn "Simulated agent". Không dùng cho evaluation thật — truyền `agent_stub=` là agent thật khi đo (spec §6.4).
- Fixture không phải dữ liệu pháp y: CAPE fixture là mẫu giả lập, `target.file.sha256` là placeholder toàn số 0 (`fixture_metadata.note`); CAPA fixture là output `capa -j` thật (capa 7.0.1, sample dotnet trong capa tests) nhưng khác mẫu CAPE. Demo cố ý băm bytes tổng hợp tại chỗ và trộn hai fixture khác nguồn để minh hoạ API — **không phải kiểm chứng tính cùng-mẫu**. `run_pipeline` chỉ kiểm định dạng sha256 (64 hex), không đối chiếu hash với artifact.

## 4. Ingestion xử lý thế nào và bằng công cụ gì

### 4.1 Ai sản xuất dữ liệu (ngoài repo)

| Nguồn | Nơi chạy | Đầu vào pipeline | Pipeline tự lấy? |
|---|---|---|---|
| CAPEv2 sandbox | VM/lab ngoài repo | JSON report đã parse (`cape_report=`) | Không — không chạy VM, không gọi API, không tải report |
| Mandiant CAPA | Ngoài repo (`capa -j`, ADR-0001) | JSON đã parse (`capa_report=`) | Không — không thực thi capa |
| Artifact bytes | Quy trình lab của caller | `artifact_bytes=` (bytes) | Không — không đọc file, không chạy binary |

### 4.2 Nhánh động — `TelemetryIngestionAdapter.ingest()` (`telemetry.py`)

- Chỉ duyệt `behavior.processes[].calls[]`; **không** đọc `network.http`/`network.dns`, không đọc memory dump.
- Allowlist tham số chính xác 6 API (mọi API/khóa khác bị bỏ qua): `OutputDebugStringA/W` → `lpOutputString`; `SetWindowTextA/W` → `lpString`; `MessageBoxA/W` → `lpText`, `lpCaption`.
- Giải mã wide NUL-interleaved trước khi lọc; bỏ giá trị < 6 ký tự hoặc bắt đầu `0x`; mỗi chuỗi giữ provenance JSON Pointer (`/behavior/processes/<i>/calls/<j>/arguments/<k>`) + `process_id`.
- Trả `(strings, errors, coverage)`: `errors` ghi path + lý do (không crash); `coverage=PARTIAL` khi có lỗi cấu trúc hoặc vượt trần 2.000 chuỗi.
- `extract_api_strings()` là dạng rút gọn chỉ trả `strings`; dùng `ingest()` khi cần thấy `errors`/`coverage`.

### 4.3 Nhánh tĩnh — Python extraction (`extraction.py`), không phải CAPA

- `extract_strings(bytes, sections=None)` chạy thuần Python: run ASCII in được + UTF-16LE, dài 6–256 ký tự, entropy 2.5–5.5, tối đa 2.000 chuỗi.
- `sections` chỉ có tác dụng khi bạn tự gọi `extract_strings` (ví dụ ưu tiên `.rsrc/.data/.edata/.idata/.debug`); `run_pipeline` nhận `artifact_bytes` phẳng và **không** tự parse bảng section PE.
- CAPA không tham gia bước này; output CAPA đi nhánh capability song song.

### 4.4 Chuẩn hoá rồi detector

- Lớp 0 `NormalizationEngine`: zero-width/NFKD/confusables, giải Base64/Hex depth ≤2, budget 64KB byte; giữ provenance + transform chain.
- Lớp 1 `YaraScanner` (`rules/promptware.yar`): `scan_normalized` cho chuỗi đã chuẩn hoá; `scan_bytes`/`scan_text` là API cho file/memory dump với `detection_source` do caller khai.
- Prompt Guard (Lớp 3) là detector tầng sau, không phải collector: chỉ chạy khi caller truyền `backend`; nhận **chuỗi telemetry đã chuẩn hoá** + provenance (`pipeline.py:717-719`).
- Nhánh capability `project_capabilities()` chạy độc lập: chiếu output `capa -j` qua allowlist 4 khóa `tactic`/`technique_id`/`technique_name`/`namespace`; mọi free-text bị tước.
- Định tuyến hiện tại vs kiến trúc đích: code hiện chạy `artifact_bytes → extract_strings → normalize → YARA` (`pipeline.py:636-643`); Prompt Guard **chưa** nhận nhánh static. Kiến trúc đích trong `implemention.md`/spec dự kiến cả hai nhánh đã chuẩn hoá cùng vào YARA + Prompt Guard — phần static → Prompt Guard chưa được nối.
- Cuckoo là optional tách riêng: chỉ chạy khi caller truyền `cape_report_path=`; ruleset `rules/promptware_cuckoo.yar` cần YARA build `--enable-cuckoo` (build hiện tại không có → cờ `cuckoo_unavailable`, coverage `PARTIAL`, không fallback ngầm).

### 4.5 Những gì KHÔNG có trong đường ingest

- Không fetch report, không polling API, không tự chạy/giải nén binary.
- Không có đường ingest memory dump hoặc provenance `VIRTUAL_ADDRESS`: `scan_bytes(..., DYNAMIC_MEMORY_DUMP)` tồn tại như detector API nhưng chưa có runtime evidence, và extraction không tự suy địa chỉ ảo (`extraction.py:17-20`; `reports/build-report.md` §5).
- Không nạp model theo mặc định: `backend=None` ⇒ Prompt Guard `errored`, không mạng; chỉ `TransformersPromptGuardBackend` (truyền tay) mới tải weight theo revision ghim — hiện gated.

## 5. API chính: `run_pipeline` (entry E2E)

Prototype không có CLI/server/UI. Entry E2E: `from guardrail.pipeline import run_pipeline`; các module khác (`extraction`, `telemetry`, `normalization`, `yara_scanner`, `capa_projection`, `policy`, `evidence`, `context`, `runtime`, `report`) cũng là API công khai khi cần ghép tầng.

| Tham số | Kiểu / mặc định | Ý nghĩa |
|---|---|---|
| `cape_report` | object, bắt buộc (positional) | CAPEv2 report đã parse |
| `artifact_sha256` | str, bắt buộc (keyword) | 64 hex; chỉ kiểm định dạng |
| `artifact_bytes` | bytes \| None | Bật nhánh static (extraction → normalize → YARA) |
| `capa_report` | object \| None | Output `capa -j` đã parse cho nhánh capability |
| `backend` | `PromptGuardBackend \| None` | `None` ⇒ PG errored ⇒ INCONCLUSIVE |
| `agent_stub` | callable \| None | Mặc định `SimulatedAgent` (chỉ dev/test) |
| `cape_report_path` | str \| Path \| None | Bật nhánh Cuckoo (thường unavailable) |
| `scanner` | `YaraScanner \| None` | Bơm scanner khác/lỗi cho test |
| `dispatcher_store` | store \| None | Cấp Read-Only Dispatcher cho agent |
| `canaries` | Sequence[str] | Canary cấp ở kênh system, kiểm ở output cuối |
| `model`, `year`, `first_evidence_sequence`, `max_re_asks`, `prompt_guard_config`, `prompt_guard_budget`, `file_type`, `packer_detected` | mặc định | Metadata, budget, `evidence_id` tất định |

Backend/agent:

- `backend=None` (khuyến nghị offline): `META_PROMPT_GUARD` ghi `errored` → `INCONCLUSIVE`, không có âm tính giả.
- Backend thật: `TransformersPromptGuardBackend(model_id=..., revision=..., device="cpu")` (keyword-only; `device` mặc định `"cpu"`); nên lấy config qua `pinned_config()` đọc `reports/integration-pin.json`. Cần `transformers`+`torch` và quyền tải `meta-llama/Prompt-Guard-86M` (hiện 401 — mục 7). Không tự tải model nếu không truyền backend.
- Agent thật: truyền `agent_stub=` (callable nhận `AgentRequest`, trả report). `SimulatedAgent` mặc định chỉ để smoke E2E; nhãn "Simulated agent" nằm trong `executive_summary`.

Trả về `PipelineResult` (NamedTuple): `artifact_sha256`, `processing_state`, `detection_state`, `decision`, `detector_results`, `required_detectors`, `capabilities`, `evidence`, `payload`, `agent_invoked`, `report`, `report_outcome`, `canary`, `limitations`; `as_dict()`/`to_json()` để xuất tất định. Tất định trong cấu hình offline (mặc định `SimulatedAgent`, `backend=None`, config cố định, không mạng/thời gian thực); backend/agent thật có thể cho kết quả khác giữa các lần chạy.

## 6. Test

Minimal, không ghi coverage vào repo:

```bash
.venv/bin/python -m pytest -q tests/test_contracts.py tests/test_telemetry.py tests/test_pipeline.py
.venv/bin/python -m pytest -q          # toàn bộ suite offline, không model thật
```

Chỉ khi cần coverage, trỏ file ra thư mục tạm để không ghi `.coverage` vào repo. Cần `pytest-cov` (tuỳ chọn; `.venv` hiện có 7.1.0 — nếu thiếu: `.venv/bin/python -m pip install "pytest-cov==7.1.0"`):

```bash
tmp=$(mktemp -d)
COVERAGE_FILE="$tmp/.coverage" .venv/bin/python -m pytest -q \
  tests/test_contracts.py tests/test_telemetry.py tests/test_pipeline.py \
  --cov=src/guardrail --cov-report=term-missing
```

Smoke model thật là opt-in và **chưa chạy trong repo** (cần quyền HF, có thể tải weight):

```bash
GUARDRAIL_PROMPT_GUARD_SMOKE=1 .venv/bin/python -m pytest tests/test_prompt_guard.py -q
```

## 7. Known limitations (đang mở, chưa fix)

1. **Ingestion `PARTIAL` bị rơi ở pipeline:** `run_pipeline` chỉ đưa `telemetry_scan.coverage` vào coverage tổng (`pipeline.py:604`), không đưa `ingestion.coverage`; lỗi cấu trúc telemetry vì thế có thể không hạ `processing_state` (`telemetry.py:140-157`).
2. **Validator report không đối chiếu SHA/cờ:** `validate_final_report` chỉ kiểm schema (pattern 64 hex), tham chiếu `evidence_id`, verdict bị cấm và ràng buộc abstention — không so `sample_metadata.sha256` với artifact thật, không bắt buộc `status_flags` theo ô ma trận (`report.py:177-221`).
3. **Fallback che finding dương:** `build_fallback_report` luôn ghi `adversarial_evasion_findings.prompt_injection_detected=false` và `evasion_attempts=[]` (`report.py:314-317`) — bằng chứng dương chỉ còn trong kho evidence, không vào report.
4. **Telemetry không có trần byte:** adapter giới hạn số chuỗi (2.000) nhưng không giới hạn độ dài/byte một chuỗi (khác extraction có max 256 ký tự) (`telemetry.py:140-157`).
5. **Provenance chuỗi trùng không nhất quán:** bản trùng vẫn được đưa qua detector; YARA dedupe giữ finding của bản xuất hiện đầu tiên (`pipeline.py:272-289`), còn `provenance_by_text` dùng cho Prompt Guard bị bản cuối ghi đè (`pipeline.py:587`) → finding PG của chuỗi trùng mang provenance bản cuối; provenance giữa hai nhánh không được hợp nhất.
6. **Chưa đo được thật:** Prompt Guard model gated (401) nên chưa có `reports/prompt_guard_measurements.json`; module Cuckoo không có trong build YARA local (`cuckoo_unavailable`); Phase 3 mới có protocol/harness — `reports/evaluation_results.synthetic-example.json` là số liệu harness, **không phải bằng chứng hiệu quả**.
7. **Fixture không phải pháp y:** fixture CAPE tổng hợp với hash placeholder toàn 0; `run_pipeline` không kiểm CAPE/CAPA cùng một sample. Production phải tự xác minh sha256 mẫu thật và nguồn cùng-mẫu trước khi tin kết quả.

Chi tiết blocked/waiver: `reports/build-report.md` §5.

## 8. Tài liệu liên quan

- [AGENTS.md](AGENTS.md) — ràng buộc an toàn khi thao tác trong repo; [CONTEXT.md](CONTEXT.md) — ubiquitous language.
- [specs/guardrail_malware_agent_spec.md](specs/guardrail_malware_agent_spec.md) — spec kỹ thuật hiện hành.
- [src/guardrail/README.md](src/guardrail/README.md) — module map, test seams, artifacts, blocked items.
- [docs/adr/](docs/adr/) — 0001 tách CAPA khỏi CAPEv2, 0002 tag-as-evidence, 0003 passive consumer agent, 0004 jsonschema làm validator report.
- [PLAN.md](PLAN.md), [implemention.md](implemention.md) — kế hoạch Phase 2 và task T01–T10.
- [reports/build-report.md](reports/build-report.md) — build waves, bug ledger, residuals, waivers; [memory/lessons-learned.md](memory/lessons-learned.md) — bài học vận hành.
