# Full-project review — 20 phát hiện mới (Spec + Standards) và baseline pyright

- **Ngày:** 2026-09-20
- **Trạng thái:** In progress — P1 đóng (SP-01, SP-02); P2 đóng một phần (SP-04, ST-01..ST-04, AC-06); còn lại Open (lý do deferral ở §8)
- **Ưu tiên:** P1 (do SP-01, SP-02)
- **Loại:** Code Review / Spec Compliance / Static Analysis
- **Phạm vi:** toàn repo, diff `ab51ed9...HEAD` (28 commit, prototype Phase 2, spec v1.4.0)
- **Loại trừ:** L01–L07 và A1–A4 đã ghi trong `issues/issue_2026-09-19_readme_known_limitations.md` và `issues/issue_2026-09-20_code_review_known_limitations.md` — review này chỉ ghi phát hiện **mới**.

---

## 1. Mục tiêu & Phương pháp

Review toàn project theo hai trục độc lập chạy song song (giống quy trình `/code-review`):

- **Trục Spec** — đối chiếu code với `specs/guardrail_malware_agent_spec.md` v1.4.0, task T01–T08 của `implemention.md`, gate `PLAN.md`, và bảng ATLAS với snapshot `ATLAS-2026.09.yaml` (đã fetch primary source, xem §3 SP-04).
- **Trục Standards** — đối chiếu với `AGENTS.md`, `CONTEXT.md` (đúng thuật ngữ `_Avoid_`), `README.md`, `src/guardrail/README.md`, `memory/lessons-learned.md`, `reports/build-report.md`, kèm smell baseline Fowler (Refactoring ch.3).

Bổ sung: phân tích tĩnh pyright (basic mode, theo `pyrightconfig.json`) và chạy lại test baseline.

Bằng chứng tái lập:

```bash
wsl.exe -e bash -c 'cd "/mnt/d/Năm 4/PTMD" && .venv/bin/python -m pytest -q'
# 486 passed, 1 skipped in 5.03s  (khớp build-report; 487 collected)

npx --yes pyright --outputjson
# 276 errors, 2 warnings / 34 files (chi tiết §5)
```

Không thực thi sample/binary nào; mọi repro là script in-memory. Probe yara-python chạy trên rule `condition: true` tự tổng hợp.

---

## 2. Trục Spec — SP-01 … SP-10 (P1×2, P2×3, P3×5)

### SP-01 — [P1] Kênh nạp report cho YARA Cuckoo sai ở cả spec lẫn code ⇒ detector Cuckoo là no-op cấu trúc

- **Vị trí:** `specs/guardrail_malware_agent_spec.md:240`, `links.md:15`, `src/guardrail/yara_scanner.py:435-437`.
- **Chuỗi sai lệch:**
  1. `links.md:15` viết `yara -x cuckoo=behavior_report.json rules.yar target_file` như một cách truyền report. Theo tài liệu YARA CLI, `-x` chính là `--module-data=MODULE=FILE` (nạp nội dung file vào module), còn external variable là `-d`. Spec §3.2.2 (dòng 240) kế thừa nhầm lẫn này và **cấm nhầm đúng kênh**: "`--module-data`/`modules_data` là kênh module-data riêng của YARA, không dùng để nạp report Cuckoo".
  2. Code bám theo spec bằng `externals={"cuckoo": str(path)}` — trong yara-python, `externals` chỉ định nghĩa *biến điều kiện* dùng trong `condition:`, không cấp dữ liệu cho module `cuckoo.*`.
- **Probe tái lập (yara-python 4.5.4, máy này):**
  ```text
  modules_data kwarg: ACCEPTED          # kwarg đúng đang có sẵn
  externals unused: silently accepted   # call hiện tại không bao giờ lỗi → lỗi im lặng
  ```
  Rule mẫu của spec (dòng 243–249, `cuckoo.network.http_user_agent(...)`) không bao giờ khớp vì module không nhận dữ liệu; `[INFERENCE]` về hành vi runtime chính xác của module khi thiếu data (chuẩn YARA: condition phụ thuộc module rỗng triệt tiêu về false). Kết quả: kể cả khi build YARA có `--enable-cuckoo` (hiện đang là waiver L06), detector Cuckoo vẫn không thể phát hiện gì.
- **Đề xuất:** (1) errata `links.md` §1.1 + spec §3.2.2 theo tài liệu YARA CLI primary (sửa spec theo nguồn, không phải khớp code); (2) chuyển code sang `modules_data={"cuckoo": <report bytes>}`; (3) regression test với report CAPE synthetic chứa UA độc hại khẳng định rule khớp.

### SP-02 — [P1] Predicate `IsPromptware` của spec §3.4 không được wire vào pipeline

- **Vị trí:** `specs/guardrail_malware_agent_spec.md` §3.4; `src/guardrail/prompt_guard.py:355-366`; `src/guardrail/pipeline.py:486-512`.
- **Bằng chứng:** `grep -rn is_promptware src/` chỉ thấy định nghĩa (dòng 355), docstring (dòng 22) và export (dòng 103) — **không có caller production**. `_prompt_guard_findings` promote *mọi* `score.detected` thành finding, bỏ qua công thức §3.4: `IsPromptware = ModelDetected ∧ (TargetEntityIsLLM ∨ InstructionOverrideContext)`. Cơ chế chống FPR Nhóm-3 của spec vắng mặt trên đường tích hợp, dù T05 được đánh dấu hoàn thành.
- **Đề xuất:** wire predicate vào `_prompt_guard_findings` với ngữ cảnh caller cung cấp; regression test: Prompt Guard detected nhưng không phải target-LLM/không override-context ⇒ không sinh finding.

### SP-03 — [P2] "Kho điều tra" (investigation store) chỉ tồn tại trên giấy

- **Vị trí:** spec §2 Lớp 4 ("raw text băm SHA-256 lưu kho điều tra riêng"), §3.5.1 (PIPELINE_ABSTENTION "kèm raw telemetry"); `evidence.py:18,501` (chỉ docstring); `pipeline.py:774-777` (abstention chỉ mang pointer provenance).
- Không có cấu trúc lưu trữ nào lưu hash của raw text ⇒ finding §4.1 không thể tái kiểm từ kho điều tra như spec yêu cầu.

### SP-04 — [P2] Bảng tên ATLAS trong `pipeline.py` sai so với snapshot đã ghim (đã đối chiếu primary)

- **Vị trí:** `src/guardrail/pipeline.py:96-111` (comment tự tuyên bố "snapshot 2026.09"); primary: `ATLAS-2026.09.yaml` (github.com/mitre-atlas/atlas-data, dist/v6).
- Đã fetch và xác nhận:
  - `AML.T0043.001` = **"Black-Box Optimization"** (yaml dòng 2539-2540) — code ghi "Craft Adversarial Data: Backdoor ML Model". `AML.T0043` (parent) = "Craft Adversarial Data" thì đúng.
  - `AML.T0048` = **"External Harms"** (yaml dòng ~2685) — code ghi "Societal Harm".
- Hiện các mã này là dead entries (detector chỉ emit T0051.001) nhưng vi phạm quy tắc verify-before-assert của AGENTS.md và sẽ phát tên sai khi được dùng.

### SP-05 — [P2] Nhánh static không được quét bởi Prompt Guard

- **Vị trí:** `src/guardrail/pipeline.py:717-719` — chỉ `telemetry_normalized` được đưa vào `META_PROMPT_GUARD`.
- Khi phân tích `artifact_bytes` (nhánh tĩnh), chuỗi nghi vấn từ `extraction.py` không bao giờ tới ML detector, trong khi spec §3.4 yêu cầu ML quét "chuỗi nghi vấn" của nhánh phát hiện tương ứng.

### SP-06 … SP-10 — [P3]

| ID | Vị trí | Nội dung |
|---|---|---|
| SP-06 | `pipeline.py:718` | Truncation `prompt_guard_budget` im lặng — spec §3.2.1 đòi ghi cờ khi cắt cụt. |
| SP-07 | `extraction.py:131-136` | Trích xuất UTF-16LE bị thu hẹp còn printable-ASCII code units, hẹp hơn §3.2.1 ("Chuỗi ASCII và UTF-16LE"). |
| SP-08 | `evaluation/dataset_protocol.py:136-137` | Scope creep: tỷ lệ origin-balance 40/40–60/60 không có trong §6.2. |
| SP-09 | `pipeline.py:113-125` | Scope creep: vocabulary OWASP/ATLAS vượt bảng §5 của spec (T0043→PROMPT_INJECTION, T0057→LLM07…). |
| SP-10 | `src/guardrail/` | Nhánh "YARA Memory Scan" (§2) không thể chạm qua `run_pipeline` — không producer `VIRTUAL_ADDRESS`. |

---

## 3. Trục Standards — ST-01 … ST-10 (P2×4, P3×6)

Kiểm chứng chéo đã thấy đúng: build-report khớp collect count (487), README quickstart reproduce được trong WSL, không vi phạm thuật ngữ `_Avoid_` của `CONTEXT.md`, module map khớp file thật.

### ST-01 — [P2] `pyproject.toml` thiếu hard dependency `yara`

- `pyproject.toml:10-12` chỉ khai báo `jsonschema`; nhưng `pipeline.py:84` hard-import `yara_scanner` và `yara_scanner.py:68` `import yara`. `pip install .` cho ra package vỡ ngay entry point; README §2 ghi workaround thay vì sửa manifest.

### ST-02 — [P2] Tooling không liên quan nằm untracked ở repo root (vi phạm tiền lệ LL-013)

- `node_modules/` (~43MB) + `package.json`/`package-lock.json` ghim dependency `opencode-antigravity-auth` (tooling AI-agent, không phải artifact project), cùng `HD.md` (tự đánh dấu SUPERSEDED, nằm ngoài doc map của AGENTS.md), `config_env/`, `guides/*.html`. `.gitignore` không có entry cho `node_modules/`. Các commit trước (f1c65e1) đã kịp ignore artifact tooling — lần này chưa.

### ST-03 — [P2] `pyrightconfig.json` untracked

- Cấu hình type-check mà các review pass dựa vào không tái lập được từ fresh checkout. Nên track (như `pyproject.toml`) hoặc xoá nếu không coi type-check là gate (xem §4).

### ST-04 — [P2] Hồ sơ review chưa được commit

- Hai issue review trước (`issue_2026-09-19_readme_known_limitations.md`, `issue_2026-09-20_code_review_known_limitations.md`) đang untracked dù AGENTS.md chỉ định `issues/` là lịch sử review và README §7 (L01–L07) phụ thuộc chúng. Mâu thuẫn với văn hoá artifact kiểm chứng được (LL-002/LL-003).

### ST-05 … ST-10 — [P3]

| ID | Vị trí | Nội dung |
|---|---|---|
| ST-05 | `README.md` §1 vs `reports/environment.json` | Citation vượt phạm vi artifact: README dẫn environment.json làm bằng chứng cho cả venv đã kiểm (yara-python 4.5.4, pytest-cov, transformers/torch) nhưng manifest chỉ liệt kê jsonschema+pytest — vi phạm LL-003. |
| ST-06 | `runtime.py:459-470` | Duplicated Code: hai nhánh `if hit.kind == "CANARY"` gán cùng `owasp`, chỉ khác chuỗi summary. |
| ST-07 | `pipeline.py:224,245,614-697` | Duplicated Code + Divergent Change: parse ATLAS-meta lặp 2 lần; wiring detector 3a/3b/3c lặp cùng shape; module 988 dòng trộn bảng data ATLAS/OWASP (96-125), `SimulatedAgent` (309-408) và E2E wiring. |
| ST-08 | `context.py:286-287` vs `runtime.py:353-359` | Chính sách duplicate bất nhất: canary trùng → raise ở context, nhưng runtime lại dedupe âm thầm cùng loại input. |
| ST-09 | `pipeline.py:127` vs `rules/promptware.yar:18` | Shotgun Surgery: `_YARA_RULE_VERSION_FALLBACK = "1.4.0"` nhân bản version meta của ruleset; bump ruleset phải sửa 2 nơi. |
| ST-10 | `policy.py:225-238`; `pipeline.py:439,749` | Primitive Obsession: `DetectorResult` TypedDict mở, key `name` không bắt buộc nhưng pipeline truy cập trực tiếp `result["name"]` — pyright xác nhận 18 diagnostic `reportTypedDictNotRequiredAccess` cùng loại. |

Lưu ý tích cực: `config_env/guardrail/model-manifest.json` trung thành ghi ProtectAI model là `BLOCKED_LABEL_CONTRACT` — không có tuyên bố gây hiểu lầm.

---

## 4. Baseline pyright (static analysis)

- **276 errors + 2 warnings / 34 file** (basic mode). Phân bố: ~54 trong `src/guardrail/`, ~222 trong `tests/`. Top rule: `reportArgumentType` 199, `reportIndexIssue` 33, `reportTypedDictNotRequiredAccess` 18, `reportReturnType` 5, `reportCallIssue` 5…
- File src nhiều nhất: `evidence.py` 15, `evaluation/dataset_protocol.py` 12, `evaluation/metrics.py` 11, `prompt_guard.py` 9, `pipeline.py` 6, `report.py` 1.
- Spot-check 3 điểm nóng (`dataset_protocol.py:413`, `prompt_guard.py:461,498`, `pipeline.py:439`): đều **không phải bug runtime** (guard `_is_number` chạy trước; Protocol stub; TypedDict do pipeline tự dựng). `[INFERENCE]` phần còn lại tương tự dạng Optional/TypedDict từ JSON parse, chưa audit từng diagnostic.
- **Quyết định cần chốt:** type-check có phải gate không? Nếu có → track `pyrightconfig.json` (ST-03), triage 276 diagnostic theo nhóm rule, bổ sung guard/TypeGuard. Nếu không → xoá config để tránh baseline đỏ giả tạo.

---

## 5. Đề xuất xử lý (thứ tự gợi ý)

1. **SP-01 + SP-02** (P1): errata spec/links rồi sửa code + regression test (xem từng mục).
2. **ST-01**: thêm `yara-python` vào `pyproject.toml` dependencies (hoặc tách optional-extra có kiểm).
3. **ST-02/03/04**: dọn `.gitignore` (node_modules, package*.json), track `pyrightconfig.json`, commit 2 issue cũ + issue này.
4. **SP-04**: sửa 2 tên ATLAS theo snapshot (một commit nhỏ, kèm test nội tệ bảng không trôi khỏi snapshot khi upgrade).
5. **SP-03/SP-05** (P2): thiết kế investigation store + đưa static strings vào đường Prompt Guard.
6. **§4 pyright**: chốt gate type-check rồi triage.

## 6. Tiêu chí nghiệm thu (Acceptance Criteria)

- [x] AC-01 (SP-01): spec §3.2.2 + links.md §1.1 đã errata theo YARA CLI primary; `yara_scanner.scan_cape_report` nạp report qua `modules_data`; test cơ chế gọi (`test_cape_report_scan_passes_report_bytes_as_module_data`) + test E2E cuckoo thật gate theo capability (skip trên build thiếu `--enable-cuckoo`).
- [x] AC-02 (SP-02): `is_promptware` được gọi trong `_prompt_guard_findings`; 4 test mới chứng minh: lọc khi thiếu ngữ cảnh (+ limitation tường minh), YARA-overlap cho qua, tham số caller `prompt_guard_target_entity_is_llm`, per-string không lan. Lưu ý: PG-positive mà không có corroboration YARA ⇒ INCONCLUSIVE + DETECTOR_DISAGREEMENT theo §3.5.1.1 (behavior có sẵn của policy, nay có test chốt).
- [x] AC-03 (SP-04): `ATLAS_TECHNIQUE_NAMES` sửa 2 entry; fixture `tests/fixtures/atlas_snapshot_subset.json` (11 tên verify nguyên văn từ snapshot 2026.09) + `tests/test_atlas_table.py` chốt không trôi.
- [x] AC-04 (ST-01): verify bằng venv sạch (uv): `pip install .` tự kéo `jsonschema` + `yara-python 4.5.4` ⇒ `import guardrail.pipeline` thành công. README §1–§2 đồng bộ.
- [x] AC-05 (ST-02/03/04): `.gitignore` thêm `package.json`/`package-lock.json` (đã có `node_modules/`); `pyrightconfig.json` + 3 issue được track. Còn mở (quyết định của chủ repo): `HD.md`, `config_env/`, `guides/` — tài liệu lab do người tạo, chưa rõ ý định track hay bỏ.
- [x] AC-06 (§4): ADR-0005 ghi quyết định pyright advisory gate + ratchet; baseline ratchet giữ nguyên sau khi sửa: **276 errors / 2 warnings** (5 diagnostics mới do test thêm đã được xử lý về net 0); pytest **494 passed, 2 skipped** (486 cũ + 8 test mới, 2 skip: 1 cũ + 1 cuckoo E2E skip trên build không có module).

## 7. Tổng kết

- **Trục Spec:** 10 phát hiện (2 P1, 3 P2, 5 P3) — nặng nhất SP-01 (Cuckoo no-op, sai từ spec xuống code) và SP-02 (predicate §3.4 chưa wire).
- **Trục Standards:** 10 phát hiện (0 P1, 4 P2, 6 P3) — nặng nhất ST-01 (dependency manifest thiếu `yara`).
- **Static analysis:** 276 diagnostics (chưa triage từng cái; spot-check không thấy bug runtime).
- Baseline test giữ nguyên: 486 passed, 1 skipped.

---

## 8. Kết quả xử lý đợt 1 (cập nhật 2026-09-20)

**Đã đóng** (commit theo lô cùng ngày; baseline sau đợt: pytest 494 passed + 2 skipped, pyright 276/2 giữ ratchet):

| Finding | Cách xử lý |
|---|---|
| SP-01 | Errata `links.md` §1.1 + spec §3.2.2 (kênh module-data, `-x` ≡ `--module-data`); `yara_scanner.scan_cape_report` dùng `modules_data={"cuckoo": bytes}` (+bắt cả `OSError` khi đọc report); comment `rules/promptware_cuckoo.yar` sửa theo; 2 test mới (probe cơ chế gọi + E2E cuckoo thật gate capability). |
| SP-02 | `_prompt_guard_findings` áp `is_promptware` per-string: `InstructionOverrideContext` suy từ overlap với chuỗi YARA flag trong cùng lượt; `TargetEntityIsLLM` là tham số caller mới `run_pipeline(..., prompt_guard_target_entity_is_llm=False)`; chuỗi bị lọc được đếm và ghi limitation tường minh (không drop im lặng). 4 test mới. Phát hiện phụ: PG-positive không corroboration YARA ⇒ INCONCLUSIVE/DETECTOR_DISAGREEMENT (§3.5.1.1) — behavior có sẵn của policy, trước giờ không test nào chạm. |
| SP-04 | 2 entry ATLAS sửa theo snapshot; fixture subset 11 tên verify nguyên văn + `test_atlas_table.py`. |
| ST-01 | `pyproject.toml` thêm `yara-python>=4.3.2` (floor theo spec §3.2.2); README §1–§2 đồng bộ; verify AC-04 bằng venv sạch. |
| ST-02/03 | `.gitignore` thêm `package.json`, `package-lock.json`; `pyrightconfig.json` track. |
| ST-04 | 3 issue được track (commit này). |
| AC-06 | ADR-0005: pyright advisory gate + ratchet; baseline 276/2 giữ nguyên net sau đợt sửa. |

**Còn mở (deferred có lý do):**

- **SP-03 (investigation store)** — cần thiết kế cấu trúc lưu Lớp 4 + ADR riêng (schema, retention, ràng buộc hash raw text); không gộp vào đợt fix code.
- **SP-05 (static strings → Prompt Guard)** — phụ thuộc test coverage cho nhánh `artifact_bytes` qua `run_pipeline` (A3 của issue 2026-09-19) và quyết định phân bổ `prompt_guard_budget` giữa hai nhánh; làm sau khi L01–L05 được sửa.
- **SP-06..SP-10, ST-05..ST-10 (P3)** — chưa lên kế hoạch; ST-08 (chính sách duplicate bất nhất) cần quyết định thiết kế, không phải fix cục bộ.
- **Pyright triage 276 diagnostics** — theo kế hoạch ratchet ADR-0005, triage theo nhóm rule trong các đợt bảo trì.
- **`HD.md` / `config_env/` / `guides/`** — chờ chủ repo quyết định track hay bỏ (không phải artifact của đợt review này).
