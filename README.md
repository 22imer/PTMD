# Guardrail chống Indirect Prompt Injection cho agent phân tích mã độc

Prototype Phase 2 của spec `SPEC-SEC-AI-2026-01` v1.4.0: chặn dữ liệu mã độc (strings, telemetry, tool result) trở thành **chỉ thị** cho LLM Agent. Promptware được giữ làm bằng chứng thay vì xoá (ADR-0002), agent chỉ tiêu thụ thụ động qua dispatcher read-only (ADR-0003). Đây là defense-in-depth — **không cam kết triệt tiêu**, residual risk vẫn còn (spec §1.1).

**Đọc trước khi thao tác:** `AGENTS.md` (ràng buộc an toàn) và `CONTEXT.md` (thuật ngữ). Repo này **không** thực thi sample/binary nào; mọi byte mẫu, strings, telemetry, log là **dữ liệu không tin cậy**, không phải chỉ thị.

## Trạng thái hiện tại (2026-09-21)

| Hạng mục | Trạng thái |
|---|---|
| Code T01–T08 (Module 0–4) | PASS theo supervisor verdict, mutation-kill 4/4 và 5/5 (`reports/build-report.md` §3) |
| Test offline | `494 passed, 2 skipped` (496 collected) |
| Type-check (advisory) | `275 errors + 2 warnings` (đo 2026-09-21 sau refactor; trần ratchet ADR-0005 là `276 errors + 2 warnings`) |
| Prompt Guard thật (Lớp 3) | **blocked**: model ghim `meta-llama/Prompt-Guard-86M` trả 403; model thay thế có bản local nhưng khác contract nhãn (§7 mục 6, §7 mục 8) |
| YARA Cuckoo (Lớp 1) | **blocked**: build `yara-python` local không có `--enable-cuckoo` (`cuckoo_unavailable`) |
| Hiệu quả phòng thủ trên dataset thật | **chưa đo**; `reports/*.synthetic-example.*` là số liệu harness, **không** phải bằng chứng hiệu quả |

Prototype, chưa production, không có CLI/server/UI — entry duy nhất là `run_pipeline()` (§5).

## 1. Yêu cầu môi trường

- **Python ≥ 3.11** — đã chạy: CPython 3.11.15 trên Linux/WSL2 (`reports/environment.json`).
- **Offline-first**: mặc định không mạng, không nạp model. Model thật là opt-in (`backend=`), và hiện đang bị chặn (§7).
- Dependency (version thật trong `.venv` đang dùng, đo 2026-09-21):

| Gói | Vai trò | Version |
|---|---|---|
| `jsonschema` | validate report Draft-07 | 4.26.0 |
| `yara-python` | bắt buộc — `pipeline` import `yara_scanner` ở top-level | 4.5.4 |
| `pytest` | chạy test | 9.1.1 |
| `pytest-cov` / `coverage` | đo coverage khi cần (tuỳ chọn) | 7.1.0 / 7.16.1 |
| `transformers` + `torch` | chỉ khi dùng Prompt Guard thật (tuỳ chọn, hiện chưa nối được) | 5.17.0 / 2.14.0+cpu |
| `huggingface_hub` / `safetensors` | kéo theo bởi transformers khi nạp weight | 1.32.0 / 0.8.0 |

`pyproject.toml` khai báo đúng hai dependency: `jsonschema` và `yara-python>=4.3.2` (floor theo spec §3.2.2); `pytest` nằm ở extra `dev`; `pytest-cov` **không** được khai báo — cài tay khi cần đo coverage.

## 2. Cài đặt và chạy từ checkout

Dùng `.venv` sẵn có (khuyến nghị) — kiểm tra bằng 2 lệnh, chạy từ gốc checkout:

```bash
test -x .venv/bin/python && .venv/bin/python -V
PYTHONPATH=src .venv/bin/python -c "import jsonschema, yara, guardrail.pipeline; print('OK', yara.__version__)"
```

Tạo môi trường mới chỉ khi chưa có (không cài thêm gì vào `.venv` đang dùng):

```bash
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install "jsonschema==4.26.0" "yara-python==4.5.4" "pytest==9.1.1" "pytest-cov==7.1.0"
fi
```

Thiếu lẻ gói nào thì cài đúng gói đó, ví dụ `.venv/bin/python -m pip install "yara-python==4.5.4"`.

**Không chạy bằng `pip install .`**: wheel cài được package `guardrail` kèm dependency nhưng **thiếu dữ liệu** — `rules/`, `schemas/`, `reports/integration-pin.json`, `src/guardrail/data/confusables_min.json` được resolve từ source tree qua `Path(__file__).resolve().parents[2]`. Luôn chạy từ gốc checkout với `PYTHONPATH=src`; `pytest` tự lấy `pythonpath = ["src"]` từ `pyproject.toml`.

## 3. Quickstart: chạy E2E trên fixture vô hại

Chạy đúng heredoc sau từ gốc checkout. Demo chỉ đọc fixture, không ghi đè fixture/artifact; JSON đầu ra chỉ ghi khi bạn tự đặt `GUARDRAIL_DEMO_JSON`.

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
    backend=None,                      # mặc định offline: khai báo rõ, không tự tải model
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

Đầu ra tất định (đã chạy lại với `.venv` hiện có, 2026-09-21):

```text
artifact_sha256 : b92d9ac98df0976ac5d771b6d6788ea3809b3165ce325f58ae104bd11078202b
state           : COMPLETE | detection: INCONCLUSIVE | action: CAUTIOUS_QUARANTINE | forward: True
detectors       : [('TELEMETRY_ADAPTER', True, False), ('YARA_STATIC', False, False), ('META_PROMPT_GUARD', False, True)]
capabilities    : 5 [{'tactic': 'Defense Evasion', 'technique_id': 'T1140', …}, {'tactic': 'Discovery', 'technique_id': 'T1083', …}]
evidence        : 2 bản ghi quarantine
agent_invoked   : True | report_status: COMPLETE | verdict: MALICIOUS | attempts: 1
  limitation: Prompt Guard không có backend (model gated) — detector bắt buộc errored.
executive_summary: Simulated agent: 2 bản ghi đối kháng, 5 capability ATT&CK; kết luận MALICIOUS.
```

Đọc kết quả:

- `META_PROMPT_GUARD errored=True` vì `backend=None` (mặc định offline; model ghim hiện trả 403) → detector **bắt buộc lỗi** → `detection_state=INCONCLUSIVE` → policy `CAUTIOUS_QUARANTINE`. Đây **không** phải kết luận âm tính, và chuỗi `limitations` nói rõ lý do.
- `verdict=MALICIOUS` đến từ `SimulatedAgent` mặc định (heuristic: có capability ⇒ MALICIOUS) và `executive_summary` tự ghi nhãn "Simulated agent". Không dùng cho evaluation thật — truyền `agent_stub=` là agent thật khi đo (spec §6.4).
- Fixture **không** phải dữ liệu pháp y: CAPE fixture là mẫu giả lập với `target.file.sha256` placeholder toàn 0; CAPA fixture là output `capa -j` thật (capa 7.0.1, sample dotnet trong capa tests) nhưng **khác mẫu** CAPE. Demo cố ý băm bytes tổng hợp và trộn hai fixture khác nguồn để minh hoạ API — không phải kiểm chứng tính cùng-mẫu. `run_pipeline` chỉ kiểm **định dạng** sha256 (64 hex), không đối chiếu hash với artifact.

## 4. Ingestion: dữ liệu vào pipeline bằng gì

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

### 4.3 Nhánh tĩnh — extraction thuần Python (`extraction.py`), không phải CAPA

- `extract_strings(bytes, sections=None)`: run ASCII in được + UTF-16LE, dài 6–256 ký tự, entropy 2.5–5.5, tối đa 2.000 chuỗi.
- `sections` chỉ có tác dụng khi bạn tự gọi `extract_strings` (ví dụ ưu tiên `.rsrc/.data/.edata/.idata/.debug`); `run_pipeline` nhận `artifact_bytes` phẳng và **không** tự parse bảng section PE.
- CAPA không tham gia bước này; output CAPA đi nhánh capability song song.

### 4.4 Lớp 0 → detector, và định tuyến hiện tại

- **Lớp 0** `NormalizationEngine`: zero-width/NFKD/confusables, giải Base64/Hex depth ≤ 2, budget 64KB byte; giữ provenance + transform chain.
- **Lớp 1** `YaraScanner` (`rules/promptware.yar`): `scan_normalized` cho chuỗi đã chuẩn hoá; `scan_bytes`/`scan_text` là API cho file/memory dump với `detection_source` do caller khai.
- **Lớp 3** Prompt Guard là detector tầng sau, không phải collector: chỉ chạy khi caller truyền `backend`, và nhận **chuỗi telemetry đã chuẩn hoá** + provenance (`pipeline.py:766-767`). Nhánh static **chưa** được nối vào Prompt Guard (SP-05).
- **Nhánh capability** `project_capabilities()` chạy độc lập: chiếu output `capa -j` qua allowlist 4 khóa `tactic`/`technique_id`/`technique_name`/`namespace`; mọi free-text bị tước.
- **Cuckoo** tách riêng, optional: chỉ chạy khi caller truyền `cape_report_path=`; ruleset `rules/promptware_cuckoo.yar` cần YARA build `--enable-cuckoo`. Build hiện tại không có → cờ `cuckoo_unavailable`, coverage `PARTIAL`, không fallback ngầm.

### 4.5 Không có trong đường ingest

- Không fetch report, không polling API, không tự chạy/giải nén binary.
- Không có đường ingest memory dump hay provenance `VIRTUAL_ADDRESS`: `scan_bytes(..., DYNAMIC_MEMORY_DUMP)` tồn tại như detector API nhưng chưa có runtime evidence, và extraction không tự suy địa chỉ ảo (`extraction.py:17-20`; `reports/build-report.md` §5).
- Không nạp model theo mặc định: `backend=None` ⇒ Prompt Guard `errored`, không mạng. Chỉ `TransformersPromptGuardBackend` (truyền tay) mới nạp weight theo revision đã ghim — model ghim hiện trả 403 nên **chưa lần nào** nạp được weight thật; model thay thế đã có bản local nhưng chưa nối vào detector (§7 mục 6, §7 mục 8).

## 5. API chính: `run_pipeline` (entry E2E)

`from guardrail.pipeline import run_pipeline`. Các module khác (`extraction`, `telemetry`, `normalization`, `yara_scanner`, `capa_projection`, `policy`, `evidence`, `context`, `runtime`, `report`) cũng là API công khai khi cần ghép tầng.

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

Backend và agent:

- `backend=None` (khuyến nghị offline): `META_PROMPT_GUARD` ghi `errored` → `INCONCLUSIVE`, không có âm tính giả.
- Backend thật: `TransformersPromptGuardBackend(model_id=..., revision=..., device="cpu")` (keyword-only, `device` mặc định `"cpu"`); lấy config qua `pinned_config()` đọc `reports/integration-pin.json`. Cần `transformers`+`torch`. Không tự nạp model nếu không truyền backend.
  - Model tham chiếu spec §3.4 `meta-llama/Prompt-Guard-86M` @ `1209add6ca7d9c1d815171b8e5571587fe3e7b03` trả **403** (`awaiting a review from the repo authors`) ⇒ backend không nạp được, pin giữ nguyên (§7 mục 6).
  - Model thay thế `meta-llama/Llama-Prompt-Guard-2-86M` @ `a8ded8e697ce7c355e395a0df51f94adb4a2fd27` tải được và đã có bản local, nhưng **chưa nối được** vì khác contract nhãn (§7 mục 8).
- Agent thật: truyền `agent_stub=` (callable nhận `AgentRequest`, trả report). `SimulatedAgent` chỉ để smoke E2E.

Trả về `PipelineResult` (NamedTuple): `artifact_sha256`, `processing_state`, `detection_state`, `decision`, `detector_results`, `required_detectors`, `capabilities`, `evidence`, `payload`, `agent_invoked`, `report`, `report_outcome`, `canary`, `limitations`; tiện ích `report_status`/`verdict` (đọc từ `report`), `as_dict()`, `to_json()` (khóa sắp xếp, hai lần chạy cùng đầu vào cho cùng chuỗi byte). `payload` là `SpotlightedPayload | None` — `None` khi `agent_invoked=False` (hàng FAILED của §3.5.1: pipeline không hỏi agent). Tất định trong cấu hình offline (mặc định `SimulatedAgent`, `backend=None`, config cố định, không mạng/thời gian thực); backend/agent thật có thể cho kết quả khác giữa các lần chạy.

## 6. Test & kiểm tra

Toàn bộ suite offline (không model thật, không ghi coverage vào repo):

```bash
.venv/bin/python -m pytest -q                                  # 494 passed, 2 skipped (496 collected)
.venv/bin/python -m pytest -q tests/test_contracts.py tests/test_telemetry.py tests/test_pipeline.py
.venv/bin/python -m pytest -q tests/evaluation                 # protocol + harness Phase 3
```

2 test skip là opt-in/capability: smoke model thật (`GUARDRAIL_PROMPT_GUARD_SMOKE`) và happy-path Cuckoo (build YARA thiếu `--enable-cuckoo`).

Coverage — trỏ file ra thư mục tạm để không ghi `.coverage` vào repo (cần `pytest-cov`, cài tay nếu thiếu: `.venv/bin/python -m pip install "pytest-cov==7.1.0"`):

```bash
tmp=$(mktemp -d)
COVERAGE_FILE="$tmp/.coverage" .venv/bin/python -m pytest -q \
  tests/test_contracts.py tests/test_telemetry.py tests/test_pipeline.py \
  --cov=src/guardrail --cov-report=term-missing
```

Type-check là **gate advisory có ratchet**, không chặn (ADR-0005):

```bash
pyright          # 276 errors, 2 warnings — không được tăng so với baseline này
```

Smoke model thật là opt-in và **chưa chạy trong repo**: test ghim cứng `load_pin()` (`meta-llama/Prompt-Guard-86M`), mà model pin hiện trả 403 — nên chạy nó với model khác **không** chỉ là đổi biến môi trường, phải sửa source/pin:

```bash
GUARDRAIL_PROMPT_GUARD_SMOKE=1 .venv/bin/python -m pytest tests/test_prompt_guard.py -q
```

Kiểm tra riêng artifact Prompt Guard thay thế (không qua pipeline, không đổi repo):

```bash
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 .venv/bin/python -c "
from transformers import AutoModelForSequenceClassification
m = AutoModelForSequenceClassification.from_pretrained(
    'meta-llama/Llama-Prompt-Guard-2-86M',
    revision='a8ded8e697ce7c355e395a0df51f94adb4a2fd27')
print(m.config.num_labels, dict(m.config.id2label))"   # 2 {0: 'LABEL_0', 1: 'LABEL_1'}
```

## 7. Known limitations (đang mở, chưa fix)

1. **Ingestion `PARTIAL` bị rơi ở pipeline:** `run_pipeline` chỉ đưa `telemetry_scan.coverage` vào coverage tổng (`pipeline.py:639`), còn `ingestion.coverage` chỉ dùng để phát hiện `FAILED` (`pipeline.py:643-644`) — lỗi cấu trúc telemetry vì thế chỉ xuất hiện dưới dạng dòng `limitations` (`pipeline.py:611-614`), không hạ `processing_state` (`telemetry.py:144-155`).
2. **Validator report không đối chiếu SHA/cờ:** `validate_final_report` chỉ kiểm schema (pattern 64 hex), tham chiếu `evidence_id`, verdict bị cấm và ràng buộc abstention — không so `sample_metadata.sha256` với artifact thật, không bắt buộc `status_flags` theo ô ma trận (`report.py:177-221`).
3. **Fallback che finding dương:** `build_fallback_report` luôn ghi `adversarial_evasion_findings.prompt_injection_detected=false` và `evasion_attempts=[]` (`report.py:314-317`) — bằng chứng dương chỉ còn trong kho evidence, không vào report.
4. **Telemetry không có trần byte:** adapter giới hạn **số chuỗi** (`MAX_STRINGS`, kiểm ở `telemetry.py:146-148`) nhưng không giới hạn độ dài/byte của một chuỗi (extraction thì cắt ở 256 ký tự) — chuỗi telemetry dài vì thế đi nguyên vẹn vào Lớp 0/detector (`telemetry.py:135-155`).
5. **Provenance chuỗi trùng không nhất quán:** bản trùng vẫn được đưa qua detector; YARA dedupe giữ finding của bản xuất hiện đầu tiên (`pipeline.py:273`, gọi tại `639/679/713`), còn dict `provenance_by_text` dùng cho Prompt Guard giữ **bản cuối** (`pipeline.py:622`, trong khi dòng `limitations` nói "bản ghi đầu tiên giữ provenance" ở `623-626`) → finding PG của chuỗi trùng mang provenance bản cuối; provenance giữa hai nhánh không được hợp nhất.
6. **Chưa đo được thật:** model tham chiếu spec §3.4 `meta-llama/Prompt-Guard-86M` (revision ghim `1209add6…7b03`) vẫn chờ Meta duyệt (HTTP 403, kiểm 2026-09-21) nên chưa có `reports/prompt_guard_measurements.json`; module Cuckoo không có trong build YARA local (`cuckoo_unavailable`); Phase 3 mới có protocol/harness — `reports/evaluation_results.synthetic-example.json` là số liệu harness, **không phải bằng chứng hiệu quả**.
7. **Fixture không phải pháp y:** fixture CAPE tổng hợp với hash placeholder toàn 0; `run_pipeline` không kiểm CAPE/CAPA cùng một sample. Production phải tự xác minh sha256 mẫu thật và nguồn cùng-mẫu trước khi tin kết quả.
8. **Model Prompt Guard thay thế chưa nối được vào Lớp 3:** `meta-llama/Llama-Prompt-Guard-2-86M` @ `a8ded8e697ce7c355e395a0df51f94adb4a2fd27` đã tải về máy (2026-09-21; HF cache; `model.safetensors` 1.115.268.200 byte, sha256 `e72017dbbe89c1232dcbc4a74ce0c389db5b468c42afd05850347b2a8c5f6b09`) và nạp offline được (`HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1`; 11,7 s CPU; 278.810.882 tham số). Không drop-in: `config.json` **không** có `id2label` nên transformers tự sinh `{0: LABEL_0, 1: LABEL_1}`, và PG2 là phân loại **2 lớp** (Meta bỏ nhãn `INJECTION`) ⇒ `resolve_label_mapping` ném `PromptGuardLabelMappingError` khi `labels()`/`run()`; ngưỡng `0.75` của spec §3.4 là của Prompt-Guard-86M, **chưa** hiệu chỉnh cho PG2. Phân tách thực đo (3 câu, không qua pipeline): injection/jailbreak → index 1 (0,99947 / 0,99644), benign → index 0 (0,99950). Nối model này = thay đổi source + pin + calibration riêng.

Chi tiết blocked/waiver: `reports/build-report.md` §5.

## 8. Bản đồ tài liệu & cấu trúc repo

| Đường dẫn | Nội dung |
|---|---|
| `AGENTS.md` | Ràng buộc an toàn và quy ước khi thao tác trong repo — đọc trước. |
| `CONTEXT.md` | Ubiquitous language (kèm danh sách `_Avoid_`). |
| `specs/guardrail_malware_agent_spec.md` | Spec kỹ thuật v1.4.0 — nguồn chuẩn cho mọi contract. |
| `PLAN.md`, `implemention.md` | Kế hoạch Phase 2 và task T01–T10 kèm trạng thái. |
| `docs/adr/` | 0001 tách CAPA/CAPEv2, 0002 tag-as-evidence, 0003 passive consumer, 0004 jsonschema validator, 0005 pyright ratchet. |
| `src/guardrail/README.md` | Module map, test seam, blocked items của prototype. |
| `reports/build-report.md`, `reports/phase0-gate.json` | Build waves, bug ledger, waivers, gate. |
| `reports/integration-pin.json`, `reports/environment.json` | Pin YARA/CAPEv2/model; môi trường tái lập. |
| `reports/*.synthetic-example.*`, `tests/fixtures/` | Số liệu harness và fixture — xem cảnh báo ở §3/§7. |
| `issues/`, `memory/lessons-learned.md` | Lịch sử review; bài học vận hành (append-only, xem `memory/README.md`). |

Cấu trúc đã track: `src/guardrail/` (+ `evaluation/`, `data/`), `rules/`, `schemas/`, `tests/` (+ `evaluation/`, `fixtures/`), `docs/adr/`, `intent/`, `issues/`, `memory/`, `reports/`, `designs/`.

Ngoài git (không track, không dùng làm nguồn chuẩn): `AGENT_CONTEXT.md`, `HD.md`, `config_env/`, `guides/`, `.zcode/`, `.agents/`, `graphify-out/`, `skills-lock.json`. Trong đó `config_env/` là bộ cấu hình lab (CAPE/CAPA/Guardrail, target model khác — `protectai/deberta-v3-base-prompt-injection-v2`) và `HD.md` là bản hướng dẫn cũ giữ để tham chiếu lịch sử.
