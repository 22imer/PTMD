"""Lớp 3 — Semantic ML Guardrail: dịch vụ Meta Prompt Guard-86M (spec v1.4.0 §3.4).

Dịch vụ phân loại văn bản đã chuẩn hoá (output của Lớp 0) thành một trong ba
nhãn của model `meta-llama/Prompt-Guard-86M` (DeBERTa-v2 sequence classification)
và quyết định "phát hiện đối kháng" theo đúng ngưỡng của spec §3.4:

    P(Injection) ≥ 0.75 HOẶC P(Jailbreak) ≥ 0.75  ⇒  adversarial

Chỉ có **một** ngưỡng 0.75. Không có quy tắc 0.50 nào trong spec hiện hành;
`PLAN.md` cũ nhắc "0.75/0.50" và đã bị T00 bác bỏ — xem `implemention.md` §4 T05.

**Nhãn lấy từ artifact, không đoán thứ tự logits.** Ánh xạ chỉ số logit → tên
nhãn được đọc từ `model.config.id2label` và chuẩn hoá bằng
`resolve_label_mapping`. Thiếu/thừa/lạ nhãn so với vocabulary
`BENIGN`/`INJECTION`/`JAILBREAK` ⇒ `PromptGuardLabelMappingError`; module không
bao giờ suy ra nhãn theo vị trí (ví dụ coi index 0 là BENIGN).

**Ngữ nghĩa Malware Command vs. Promptware (spec §3.4).**

    IsPromptware = ModelDetected ∧ (TargetEntityIsLLM ∨ InstructionOverrideContext)

Hàm `is_promptware` hiện thực đúng công thức đó. Hai biến ngữ cảnh **do caller
cung cấp**, module này không tự phát minh detector cho chúng:

- `target_entity_is_llm`: văn bản/chuỗi đang xét hướng tới một LLM (prompt,
  instruction, system message, tool description...) chứ không phải chỉ là lệnh
  shell/dữ liệu mà malware thực thi. Nguồn: contract provenance + loại nguồn
  của chuỗi (ví dụ `SANDBOX_API_LOG` của `cmd.exe` ⇒ `False`).
- `instruction_override_context`: chuỗi mang ý đồ ghi đè/phủ nhận chỉ thị trước
  đó (ignore/forget/override previous instructions...). Nguồn: kết luận của
  caller/nhánh YARA, không phải của model này.

Nếu cả hai `False`, một chuỗi có xác suất Injection cao vẫn là **malware
command**, không phải promptware — đây là cơ chế chống FPR trên Nhóm 3 khi đo
(spec §6.6). Nếu một trong hai `True`, phát hiện của model được nâng thành
promptware.

**Truncation theo coverage contract.** Sequence length tối đa là
`MAX_SEQUENCE_LENGTH = 512` (spec §6.5). Mỗi chuỗi được tokenize **không** cắt
trước để đếm token thật; nếu số token > 512 thì batch kết quả mang
`coverage = PARTIAL` và `status_flags = [TRUNCATED_ARTIFACT_FLAG]` (ma trận
§3.5.1). Phần chưa được model nhìn thấy **không** bị âm thầm coi là đã phân
tích đầy đủ.

**Lỗi/timeout tách khỏi kết quả âm tính.** Backend lỗi (thiếu dependency, không
tải được weight, forward lỗi, quá thời gian) ⇒ raise họ `PromptGuardError`; API
này **không** trả `detected=False` khi chưa thực sự chạy được model. Đây là
contract "Detector → Policy" của T00: lỗi detector không được đổi thành
`NOT_DETECTED`.

**Nạp lazy.** Model và tokenizer chỉ được tải ở lần phân loại đầu tiên (hoặc lần
đọc `labels` đầu tiên); khởi tạo `PromptGuardService` không tải weight và không
bắt buộc `torch`/`transformers` phải có mặt — điều này cho phép test logic thuần
(logits/nhãn tổng hợp) chạy trên môi trường chưa cài model.

Đo độ trễ bằng đồng hồ đơn điệu (`time.monotonic`, spec §6.5) qua
`LatencyRecorder`; `classify_batch` tự ghi mẫu mỗi lần gọi.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple, Protocol

from guardrail.contracts import ProcessingState, StatusFlag

__all__ = [
    "ADVERSARIAL_LABELS",
    "DEFAULT_BATCH_SIZE",
    "DETECTION_THRESHOLD",
    "LABEL_BENIGN",
    "LABEL_INJECTION",
    "LABEL_JAILBREAK",
    "MAX_BATCH_SIZE",
    "MAX_SEQUENCE_LENGTH",
    "MIN_BATCH_SIZE",
    "MODEL_ID",
    "PIN_PATH",
    "BackendPrediction",
    "LatencyRecorder",
    "PromptGuardBackend",
    "PromptGuardClassification",
    "PromptGuardConfig",
    "PromptGuardError",
    "PromptGuardInferenceError",
    "PromptGuardLabelMappingError",
    "PromptGuardLabels",
    "PromptGuardModelUnavailableError",
    "PromptGuardPin",
    "PromptGuardPinError",
    "PromptGuardScore",
    "PromptGuardService",
    "PromptGuardTimeoutError",
    "TransformersPromptGuardBackend",
    "is_adversarial",
    "is_promptware",
    "label_probabilities",
    "load_pin",
    "percentile",
    "pinned_config",
    "resolve_label_mapping",
    "softmax",
]

# --- Hằng số theo spec §3.4 và §6.5 ----------------------------------------

#: Model tham chiếu (spec §3.4).
MODEL_ID = "meta-llama/Prompt-Guard-86M"
#: Ngưỡng quyết định duy nhất của spec §3.4 (không có ngưỡng 0.50).
DETECTION_THRESHOLD = 0.75
#: Sequence length tối đa (spec §6.5).
MAX_SEQUENCE_LENGTH = 512
#: Batch 8–16 sequences (spec §6.5).
MIN_BATCH_SIZE = 8
MAX_BATCH_SIZE = 16
DEFAULT_BATCH_SIZE = 16

LABEL_BENIGN = "BENIGN"
LABEL_INJECTION = "INJECTION"
LABEL_JAILBREAK = "JAILBREAK"
#: Vocabulary nhãn bắt buộc của Prompt Guard-86M.
_CANONICAL_LABELS: tuple[str, ...] = (LABEL_BENIGN, LABEL_INJECTION, LABEL_JAILBREAK)
#: Hai nhãn đối kháng dùng cho ngưỡng §3.4.
ADVERSARIAL_LABELS: tuple[str, ...] = (LABEL_INJECTION, LABEL_JAILBREAK)

#: Vị trí file ghim revision tích hợp (`reports/integration-pin.json`, R04).
PIN_PATH = Path(__file__).resolve().parents[2] / "reports" / "integration-pin.json"


# --- Lỗi có cấu trúc (tách khỏi kết quả âm tính) ---------------------------


class PromptGuardError(RuntimeError):
    """Lỗi cơ sở của dịch vụ Prompt Guard."""


class PromptGuardPinError(PromptGuardError):
    """File ghim revision thiếu/không đọc được/thiếu khoá `prompt_guard`."""


class PromptGuardModelUnavailableError(PromptGuardError):
    """Không nạp được model/tokenizer (thiếu dependency, weight, quyền truy cập)."""


class PromptGuardLabelMappingError(PromptGuardError):
    """`model.config.id2label` không đúng vocabulary nhãn của Prompt Guard."""


class PromptGuardInferenceError(PromptGuardError):
    """Suy luận thất bại (forward lỗi, logits không khớp số nhãn...)."""


class PromptGuardTimeoutError(PromptGuardInferenceError):
    """Suy luận vượt `timeout_seconds`; detector chưa cho kết quả nào."""


# --- Ghim revision từ `reports/integration-pin.json` -----------------------


class PromptGuardPin(NamedTuple):
    """Model id và revision đã ghim cho Prompt Guard (R04)."""

    model_id: str
    revision: str


def load_pin(pin_path: str | Path | None = None) -> PromptGuardPin:
    """Đọc `prompt_guard.{model,revision}` từ file ghim tích hợp.

    Sai đường dẫn/JSON/khoá ⇒ `PromptGuardPinError`. Không có giá trị mặc định
    đoán sẵn cho revision: build phải khóa được đúng artifact đã thẩm định.
    """
    path = Path(pin_path) if pin_path is not None else PIN_PATH
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PromptGuardPinError(f"không đọc được file ghim {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PromptGuardPinError(f"file ghim {path} không phải JSON hợp lệ: {exc}") from exc
    section = document.get("prompt_guard") if isinstance(document, Mapping) else None
    if not isinstance(section, Mapping):
        raise PromptGuardPinError(f"file ghim {path} thiếu khoá `prompt_guard`")
    model_id = section.get("model")
    revision = section.get("revision")
    if not isinstance(model_id, str) or not model_id:
        raise PromptGuardPinError(f"file ghim {path} thiếu `prompt_guard.model`")
    if not isinstance(revision, str) or not revision:
        raise PromptGuardPinError(f"file ghim {path} thiếu `prompt_guard.revision`")
    return PromptGuardPin(model_id=model_id, revision=revision)


class PromptGuardConfig(NamedTuple):
    """Cấu hình cố định của một dịch vụ Prompt Guard.

    `revision` không có mặc định — lấy từ `load_pin()`/`pinned_config()` để mọi
    lần chạy dùng đúng artifact đã ghim.
    """

    revision: str
    model_id: str = MODEL_ID
    device: str = "cpu"
    batch_size: int = DEFAULT_BATCH_SIZE
    max_length: int = MAX_SEQUENCE_LENGTH
    injection_threshold: float = DETECTION_THRESHOLD
    jailbreak_threshold: float = DETECTION_THRESHOLD
    timeout_seconds: float | None = None

    def validate(self) -> None:
        """Kiểm các giới hạn spec §3.4/§6.5 trước khi nạp model."""
        if not self.revision:
            raise ValueError("revision rỗng: phải lấy từ file ghim tích hợp")
        if not MIN_BATCH_SIZE <= self.batch_size <= MAX_BATCH_SIZE:
            raise ValueError(
                f"batch_size phải trong [{MIN_BATCH_SIZE}, {MAX_BATCH_SIZE}] (spec §6.5), "
                f"nhận {self.batch_size}"
            )
        if self.max_length < 1:
            raise ValueError(f"max_length phải ≥ 1, nhận {self.max_length}")
        for name, threshold in (
            ("injection_threshold", self.injection_threshold),
            ("jailbreak_threshold", self.jailbreak_threshold),
        ):
            if not 0.0 <= threshold <= 1.0:
                raise ValueError(f"{name} phải trong [0, 1], nhận {threshold}")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds phải > 0, nhận {self.timeout_seconds}")


def pinned_config(pin_path: str | Path | None = None, **overrides: object) -> PromptGuardConfig:
    """Dựng `PromptGuardConfig` từ file ghim, cho phép ghi đè từng trường."""
    pin = load_pin(pin_path)
    base = PromptGuardConfig(revision=pin.revision, model_id=pin.model_id)
    return base._replace(**overrides)


# --- Logic thuần: softmax, ánh xạ nhãn, ngưỡng, predicate ------------------


class PromptGuardLabels(NamedTuple):
    """Ánh xạ chỉ số logit → tên nhãn canonical, đọc từ `model.config.id2label`."""

    mapping: dict[int, str]
    benign_index: int
    injection_index: int
    jailbreak_index: int

    def index_of(self, label: str) -> int:
        """Chỉ số logit của một nhãn canonical; lạ nhãn ⇒ `KeyError`."""
        return {
            LABEL_BENIGN: self.benign_index,
            LABEL_INJECTION: self.injection_index,
            LABEL_JAILBREAK: self.jailbreak_index,
        }[label]


def resolve_label_mapping(id2label: Mapping[object, str] | None) -> PromptGuardLabels:
    """Chuẩn hoá `model.config.id2label` thành ánh xạ nhãn canonical.

    Nhận cả khoá `int` (transformers cast sẵn) lẫn khoá `str` số (config.json);
    tên nhãn được strip + upper. Bất kỳ nhãn nào ngoài
    `BENIGN`/`INJECTION`/`JAILBREAK`, nhãn thiếu, khoá không phải số nguyên hoặc
    giá trị không phải chuỗi ⇒ `PromptGuardLabelMappingError`. Không suy diễn
    theo thứ tự logits.
    """
    if not isinstance(id2label, Mapping) or not id2label:
        raise PromptGuardLabelMappingError(
            "model.config.id2label rỗng hoặc thiếu: không xác định được ánh xạ nhãn"
        )
    mapping: dict[int, str] = {}
    for key, value in id2label.items():
        try:
            index = int(key)
        except (TypeError, ValueError) as exc:
            raise PromptGuardLabelMappingError(f"khoá id2label không phải số nguyên: {key!r}") from exc
        if index in mapping:
            raise PromptGuardLabelMappingError(f"id2label trùng chỉ số logit {index}")
        if not isinstance(value, str):
            raise PromptGuardLabelMappingError(f"nhãn tại index {index} không phải chuỗi: {value!r}")
        name = value.strip().upper()
        if name not in _CANONICAL_LABELS:
            raise PromptGuardLabelMappingError(
                f"nhãn {value!r} ngoài vocabulary Prompt Guard {_CANONICAL_LABELS}"
            )
        mapping[index] = name
    present = set(mapping.values())
    missing = [name for name in _CANONICAL_LABELS if name not in present]
    if missing:
        raise PromptGuardLabelMappingError(
            f"id2label thiếu nhãn bắt buộc {missing}; nhận {sorted(present)}"
        )
    return PromptGuardLabels(
        mapping=mapping,
        benign_index=_index_of(mapping, LABEL_BENIGN),
        injection_index=_index_of(mapping, LABEL_INJECTION),
        jailbreak_index=_index_of(mapping, LABEL_JAILBREAK),
    )


def _index_of(mapping: Mapping[int, str], name: str) -> int:
    for index, label in mapping.items():
        if label == name:
            return index
    raise PromptGuardLabelMappingError(f"thiếu nhãn {name}")  # không xảy ra sau khi validate


def softmax(logits: Sequence[float]) -> list[float]:
    """Softmax ổn định số học (trừ max trước khi exp)."""
    if not logits:
        raise PromptGuardInferenceError("logits rỗng")
    top = max(logits)
    exponentials = [math.exp(value - top) for value in logits]
    total = sum(exponentials)
    if not math.isfinite(total) or total <= 0.0:
        raise PromptGuardInferenceError(f"softmax không hợp lệ với logits {list(logits)!r}")
    return [value / total for value in exponentials]


def label_probabilities(logits: Sequence[float], labels: PromptGuardLabels) -> dict[str, float]:
    """Xác suất từng nhãn canonical từ một vector logits.

    Số logits phải khớp số nhãn; lệch ⇒ `PromptGuardInferenceError` (không cắt
    bớt hay đoán nhãn).
    """
    if len(logits) != len(labels.mapping):
        raise PromptGuardInferenceError(
            f"số logits ({len(logits)}) khác số nhãn ({len(labels.mapping)})"
        )
    probabilities = softmax(logits)
    return {name: probabilities[index] for index, name in sorted(labels.mapping.items())}


def is_adversarial(
    probabilities: Mapping[str, float],
    *,
    injection_threshold: float = DETECTION_THRESHOLD,
    jailbreak_threshold: float = DETECTION_THRESHOLD,
) -> bool:
    """True nếu P(Injection) ≥ ngưỡng HOẶC P(Jailbreak) ≥ ngưỡng (spec §3.4).

    So sánh dùng `>=`: đúng bằng 0.75 là phát hiện; 0.7499 là không.
    """
    return (
        probabilities[LABEL_INJECTION] >= injection_threshold
        or probabilities[LABEL_JAILBREAK] >= jailbreak_threshold
    )


def is_promptware(
    model_detected: bool,
    target_entity_is_llm: bool,
    instruction_override_context: bool,
) -> bool:
    """`IsPromptware = ModelDetected ∧ (TargetEntityIsLLM ∨ InstructionOverrideContext)`.

    `model_detected` là kết quả `is_adversarial` trên một chuỗi. Hai tham số còn
    lại do caller quyết định (xem module docstring): module này chỉ áp công thức
    §3.4, không tự sinh detector cho ngữ cảnh.
    """
    return bool(model_detected) and bool(target_entity_is_llm or instruction_override_context)


# --- Đo độ trễ bằng đồng hồ đơn điệu (spec §6.5) ---------------------------


def percentile(samples: Sequence[float], quantile: float) -> float:
    """Phân vị nội suy tuyến tính (kiểu numpy) trên mẫu chưa sắp xếp."""
    if not samples:
        raise ValueError("không có mẫu độ trễ để tính phân vị")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError(f"quantile phải trong [0, 1], nhận {quantile}")
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    position = quantile * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


class LatencyRecorder:
    """Thu thập mẫu độ trễ bằng đồng hồ đơn điệu và báo p50/p90/p99.

    `clock` mặc định `time.monotonic` (spec §6.5); test có thể truyền đồng hồ
    giả để tất định.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._samples: list[float] = []

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    @property
    def samples(self) -> list[float]:
        return list(self._samples)

    @property
    def count(self) -> int:
        return len(self._samples)

    def record(self, seconds: float) -> None:
        """Ghi một mẫu độ trễ (giây)."""
        self._samples.append(float(seconds))

    @contextmanager
    def measure(self) -> Iterator[None]:
        """Đo một khối lệnh và tự ghi mẫu."""
        started = self._clock()
        try:
            yield
        finally:
            self._samples.append(self._clock() - started)

    def reset(self) -> None:
        """Xoá toàn bộ mẫu đã ghi."""
        self._samples.clear()

    def percentiles(self, quantiles: Sequence[float] = (0.5, 0.9, 0.99)) -> dict[float, float]:
        """Phân vị của các mẫu hiện có, khóa là quantile."""
        return {quantile: percentile(self._samples, quantile) for quantile in quantiles}

    def summary(self) -> dict[str, float | int]:
        """Tóm tắt `count` + p50/p90/p99 (giây) để ghi vào report đo."""
        summary: dict[str, float | int] = {"count": self.count}
        summary.update({f"p{int(q * 100)}": value for q, value in self.percentiles().items()})
        return summary


# --- Backend suy luận ------------------------------------------------------


class BackendPrediction(NamedTuple):
    """Kết quả thô của một lần chạy backend cho một batch.

    `logits[i]` ứng với `texts[i]`; `token_counts[i]` là số token **trước khi
    cắt** theo `max_length` (gồm special token) — cơ sở để gắn cờ truncation.
    """

    logits: list[list[float]]
    token_counts: list[int]


class PromptGuardBackend(Protocol):
    """Giao diện suy luận tối thiểu mà `PromptGuardService` cần.

    Tách khỏi transformers để test logic (nhãn/ngưỡng/coverage) bằng backend
    tổng hợp, và để model thật là chi tiết triển khai của
    `TransformersPromptGuardBackend`.
    """

    def labels(self) -> PromptGuardLabels:
        """Ánh xạ nhãn đọc từ artifact của model."""

    def run(self, texts: Sequence[str], *, max_length: int) -> BackendPrediction:
        """Suy luận một batch chuỗi, trả logits và số token trước khi cắt."""


class TransformersPromptGuardBackend:
    """Backend mặc định: transformers + torch, nạp lazy theo revision đã ghim."""

    def __init__(self, *, model_id: str, revision: str, device: str = "cpu") -> None:
        self.model_id = model_id
        self.revision = revision
        self.device = device
        self._torch: object | None = None
        self._tokenizer: object | None = None
        self._model: object | None = None
        self._labels: PromptGuardLabels | None = None
        self._lock = threading.Lock()

    @property
    def loaded(self) -> bool:
        """True sau khi weight đã được nạp (tức đã có model trong RAM)."""
        return self._model is not None

    def labels(self) -> PromptGuardLabels:
        self._ensure_loaded()
        assert self._labels is not None
        return self._labels

    def run(self, texts: Sequence[str], *, max_length: int) -> BackendPrediction:
        tokenizer, model = self._ensure_loaded()
        torch = self._torch
        assert torch is not None
        batch = list(texts)
        try:
            # Đếm token thật (không cắt) để phát hiện truncation một cách tường minh.
            full = tokenizer(batch, add_special_tokens=True, truncation=False)["input_ids"]
            token_counts = [len(ids) for ids in full]
            encoded = tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            )
            encoded = encoded.to(self.device)
            with torch.no_grad():
                outputs = model(**encoded)
            rows = outputs.logits.detach().to("cpu").float().tolist()
        except PromptGuardError:
            raise
        except Exception as exc:  # noqa: BLE001 - chuẩn hoá mọi lỗi backend thành lỗi có cấu trúc
            raise PromptGuardInferenceError(f"forward thất bại: {exc}") from exc
        return BackendPrediction(logits=rows, token_counts=token_counts)

    def _ensure_loaded(self) -> tuple[object, object]:
        with self._lock:
            if self._model is None:
                tokenizer, model, torch = self._load()
                self._labels = resolve_label_mapping(getattr(model.config, "id2label", None))
                self._torch, self._tokenizer, self._model = torch, tokenizer, model
            assert self._tokenizer is not None and self._model is not None
            return self._tokenizer, self._model

    def _load(self) -> tuple[object, object, object]:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise PromptGuardModelUnavailableError(
                "chưa cài `torch`/`transformers` trong môi trường chạy"
            ) from exc
        try:
            tokenizer = AutoTokenizer.from_pretrained(self.model_id, revision=self.revision)
            model = AutoModelForSequenceClassification.from_pretrained(
                self.model_id, revision=self.revision
            )
        except Exception as exc:  # noqa: BLE001 - gộp lỗi mạng/auth/weight thành "không khả dụng"
            raise PromptGuardModelUnavailableError(
                f"không nạp được {self.model_id}@{self.revision}: {exc}"
            ) from exc
        model.eval()
        model.to(self.device)
        return tokenizer, model, torch


# --- Kết quả phân loại -----------------------------------------------------


class PromptGuardScore(NamedTuple):
    """Kết quả phân loại một chuỗi."""

    text: str
    probabilities: dict[str, float]
    predicted_label: str
    detected: bool
    truncated: bool
    token_count: int

    @property
    def detection_score(self) -> float:
        """Điểm đối kháng thô = max(P(Injection), P(Jailbreak)) để chuyển cho policy."""
        return max(self.probabilities[LABEL_INJECTION], self.probabilities[LABEL_JAILBREAK])


class PromptGuardClassification(NamedTuple):
    """Kết quả phân loại một batch chuỗi + coverage của lần chạy."""

    model_id: str
    revision: str
    device: str
    scores: list[PromptGuardScore]
    coverage: ProcessingState
    status_flags: list[StatusFlag]
    latency_seconds: float

    @property
    def detected(self) -> bool:
        """True nếu ≥1 chuỗi vượt ngưỡng đối kháng."""
        return any(score.detected for score in self.scores)

    @property
    def truncated(self) -> bool:
        """True nếu ≥1 chuỗi bị cắt ở `max_length`."""
        return any(score.truncated for score in self.scores)


# --- Dịch vụ ---------------------------------------------------------------


def _chunks(items: Sequence[str], size: int) -> Iterator[list[str]]:
    for start in range(0, len(items), size):
        yield list(items[start : start + size])


def _predicted_label(probabilities: Mapping[str, float]) -> str:
    return max(_CANONICAL_LABELS, key=lambda name: probabilities[name])


class PromptGuardService:
    """Phân loại chuỗi đã chuẩn hoá bằng Meta Prompt Guard-86M (spec §3.4).

    Model chỉ được nạp ở lần `classify`/`classify_batch`/`labels` đầu tiên
    (hoặc ở lần gọi `is_loaded` sau đó ít nhất một lần, vì `is_loaded` không
    kích hoạt nạp).
    """

    def __init__(
        self,
        config: PromptGuardConfig | None = None,
        *,
        backend: PromptGuardBackend | None = None,
        pin_path: str | Path | None = None,
        latency_recorder: LatencyRecorder | None = None,
    ) -> None:
        self.config = config if config is not None else pinned_config(pin_path)
        self.config.validate()
        self._backend: PromptGuardBackend = backend if backend is not None else (
            TransformersPromptGuardBackend(
                model_id=self.config.model_id,
                revision=self.config.revision,
                device=self.config.device,
            )
        )
        self._labels: PromptGuardLabels | None = None
        self._lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None
        self.latency = latency_recorder if latency_recorder is not None else LatencyRecorder()

    @property
    def model_id(self) -> str:
        return self.config.model_id

    @property
    def revision(self) -> str:
        """Revision đã dùng để nạp (từ file ghim) — dùng cho report/smoke."""
        return self.config.revision

    @property
    def device(self) -> str:
        return self.config.device

    @property
    def labels(self) -> PromptGuardLabels:
        """Ánh xạ nhãn đã resolve từ artifact; kích hoạt nạp model lần đầu."""
        if self._labels is None:
            with self._lock:
                if self._labels is None:
                    self._labels = self._backend.labels()
        return self._labels

    @property
    def is_loaded(self) -> bool:
        """True nếu model đã được nạp (backend thật) hoặc nhãn đã resolve."""
        loaded = getattr(self._backend, "loaded", None)
        if isinstance(loaded, bool):
            return loaded
        return self._labels is not None

    def classify(self, text: str) -> PromptGuardScore:
        """Phân loại một chuỗi; tương đương `classify_batch([text]).scores[0]`."""
        return self.classify_batch([text]).scores[0]

    def classify_batch(self, texts: Sequence[str]) -> PromptGuardClassification:
        """Phân loại một danh sách chuỗi theo batch 8–16, sequence length 512.

        Chuỗi rỗng ⇒ kết quả rỗng `COMPLETE`, không nạp model. Detector lỗi ⇒
        raise `PromptGuardError` (xem `_predict`), không trả kết quả âm tính giả.
        """
        items = list(texts)
        started = self.latency.clock()
        scores: list[PromptGuardScore] = []
        if items:
            labels = self.labels
            for chunk in _chunks(items, self.config.batch_size):
                prediction = self._predict(chunk)
                scores.extend(self._score_chunk(chunk, prediction, labels))
        elapsed = self.latency.clock() - started
        self.latency.record(elapsed)
        truncated = any(score.truncated for score in scores)
        return PromptGuardClassification(
            model_id=self.config.model_id,
            revision=self.config.revision,
            device=self.config.device,
            scores=scores,
            coverage=ProcessingState.PARTIAL if truncated else ProcessingState.COMPLETE,
            status_flags=[StatusFlag.TRUNCATED_ARTIFACT_FLAG] if truncated else [],
            latency_seconds=elapsed,
        )

    def _score_chunk(
        self,
        chunk: Sequence[str],
        prediction: BackendPrediction,
        labels: PromptGuardLabels,
    ) -> list[PromptGuardScore]:
        if len(prediction.logits) != len(chunk) or len(prediction.token_counts) != len(chunk):
            raise PromptGuardInferenceError(
                f"backend trả {len(prediction.logits)} logits/{len(prediction.token_counts)} "
                f"token count cho {len(chunk)} chuỗi"
            )
        scores: list[PromptGuardScore] = []
        for text, logits, token_count in zip(chunk, prediction.logits, prediction.token_counts):
            probabilities = label_probabilities(logits, labels)
            scores.append(
                PromptGuardScore(
                    text=text,
                    probabilities=probabilities,
                    predicted_label=_predicted_label(probabilities),
                    detected=is_adversarial(
                        probabilities,
                        injection_threshold=self.config.injection_threshold,
                        jailbreak_threshold=self.config.jailbreak_threshold,
                    ),
                    truncated=token_count > self.config.max_length,
                    token_count=token_count,
                )
            )
        return scores

    def _predict(self, chunk: Sequence[str]) -> BackendPrediction:
        """Chạy backend; lỗi/timeout thành lỗi có cấu trúc, không thành âm tính."""
        timeout = self.config.timeout_seconds
        try:
            if timeout is None:
                return self._backend.run(chunk, max_length=self.config.max_length)
            future = self._ensure_executor().submit(
                self._backend.run, chunk, max_length=self.config.max_length
            )
            return future.result(timeout=timeout)
        except PromptGuardError:
            raise
        except FutureTimeoutError as exc:
            raise PromptGuardTimeoutError(
                f"backend vượt timeout {timeout}s với batch {len(chunk)} chuỗi"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - mọi lỗi backend đều là lỗi detector
            raise PromptGuardInferenceError(f"backend lỗi: {exc}") from exc

    def _ensure_executor(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="prompt-guard"
                )
            return self._executor

    def close(self) -> None:
        """Giải phóng executor dùng cho timeout (nếu có)."""
        with self._lock:
            if self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=True)
                self._executor = None
