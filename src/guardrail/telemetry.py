"""Telemetry Ingestion Adapter — trích tham số văn bản từ CAPEv2 report (T02).

Đặc tả: spec v1.4.0 §3.2.2. Adapter thuộc **pha trích xuất**, chạy trước Lớp 0:
output (``RawString`` + ``Provenance`` kiểu ``JSON_LOG_POINTER``) đi qua
Normalization rồi mới tới YARA/ML. Việc quét hành vi trong report là của YARA
Cuckoo module; adapter chỉ trích tham số chuỗi thành ``RawString`` — hai cơ chế
độc lập, không thay thế nhau.

Allowlist (giữ nguyên spec §3.2.2): ``OutputDebugStringA/W`` → ``lpOutputString``;
``SetWindowTextA/W`` → ``lpString``; ``MessageBoxA/W`` → ``lpText``, ``lpCaption``.
Chỉ nhận value độ dài ≥6 và không bắt đầu bằng ``0x``.

**Thiết kế API & contract lỗi (checklist T02, contract T00 "Detector → Policy"):**

- ``ingest(cape_report) -> TelemetryIngestionResult`` là API đầy đủ. Nó không
  crash khi report thiếu trường/sai kiểu; mỗi lỗi cấu trúc được ghi thành một
  ``TelemetryError`` có ``path`` (JSON Pointer tới vị trí sai) và ``reason``.
  Report hợp lệ không có finding → ``strings=[]``, ``errors=[]``,
  ``coverage=COMPLETE``. Report sai schema/thiếu dữ liệu → ``errors`` khác rỗng,
  ``coverage=PARTIAL`` (spec §3.2.2: "report thiếu trường bắt buộc ⇒ lỗi schema
  và processing state PARTIAL"). Lỗi detector **không** bị đổi thành
  ``NOT_DETECTED``.
- ``extract_api_strings(cape_report) -> list[dict]`` là dạng trả về đúng chữ ký
  spec §3.2.2 (chỉ danh sách chuỗi). Dùng ``ingest`` khi cần thấy ``errors``/
  ``coverage``.

``network.http``/``network.dns`` ngoài phạm vi adapter (spec §3.2.2) và không bị
đồng nhất với API arguments; URL/network do đường dẫn khác xử lý.

Ngân sách 2.000 chuỗi/mẫu của pha trích xuất (spec §3.2.1) cũng áp cho adapter:
tham số ``max_strings`` (mặc định ``MAX_STRINGS``); vượt trần → dừng trích và
``coverage=PARTIAL``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import NamedTuple, NotRequired, TypedDict

from guardrail.contracts import ProcessingState, Provenance, ProvenanceType
from guardrail.extraction import MAX_STRINGS, RawString

__all__ = [
    "TelemetryError",
    "TelemetryIngestionAdapter",
    "TelemetryIngestionResult",
    "TelemetryString",
]

_MIN_VALUE_LENGTH = 6
_HEX_PREFIX = "0x"


class TelemetryString(RawString):
    """``RawString`` trích từ API trace, giữ thêm ``api`` và ``timestamp``.

    Metadata API/timestamp không làm thay đổi độ tin cậy của text (contract T00).
    """

    api: str
    timestamp: NotRequired[str | None]


class TelemetryError(TypedDict):
    """Một lỗi cấu trúc report: ``path`` là JSON Pointer, ``reason`` là mô tả."""

    path: str
    reason: str


class TelemetryIngestionResult(NamedTuple):
    """Kết quả ``ingest``: chuỗi trích được, lỗi cấu trúc và coverage.

    ``coverage`` là ``COMPLETE`` khi không có lỗi và không chạm ngân sách, ngược
    lại là ``PARTIAL``.
    """

    strings: list[TelemetryString]
    errors: list[TelemetryError]
    coverage: ProcessingState


def _error(path: str, reason: str) -> TelemetryError:
    return TelemetryError(path=path, reason=reason)


def _type_name(value: object) -> str:
    return type(value).__name__


class TelemetryIngestionAdapter:
    """Trích tham số văn bản allowlist từ CAPEv2 JSON report."""

    TEXT_ARG_ALLOWLIST: dict[str, tuple[str, ...]] = {
        "OutputDebugStringA": ("lpOutputString",),
        "OutputDebugStringW": ("lpOutputString",),
        "SetWindowTextA": ("lpString",),
        "SetWindowTextW": ("lpString",),
        "MessageBoxA": ("lpText", "lpCaption"),
        "MessageBoxW": ("lpText", "lpCaption"),
    }

    def __init__(self, max_strings: int = MAX_STRINGS) -> None:
        if max_strings < 0:
            raise ValueError("max_strings phải >= 0")
        self.max_strings = max_strings

    def ingest(self, cape_report: object) -> TelemetryIngestionResult:
        """Trích chuỗi + thu lỗi cấu trúc mà không crash (xem docstring module)."""
        errors: list[TelemetryError] = []
        strings: list[TelemetryString] = []
        truncated = False

        for item in self._iter_strings(cape_report, errors):
            if len(strings) >= self.max_strings:
                truncated = True
                break
            strings.append(item)

        coverage = (
            ProcessingState.COMPLETE
            if not errors and not truncated
            else ProcessingState.PARTIAL
        )
        return TelemetryIngestionResult(strings, errors, coverage)

    def extract_api_strings(self, cape_report: object) -> list[TelemetryString]:
        """Dạng trả về đúng chữ ký spec §3.2.2: chỉ danh sách chuỗi trích được.

        Lỗi cấu trúc bị bỏ qua ở dạng này; dùng :meth:`ingest` để thấy ``errors``
        và ``coverage``.
        """
        return self.ingest(cape_report).strings

    def _iter_strings(
        self, cape_report: object, errors: list[TelemetryError]
    ) -> Iterator[TelemetryString]:
        if not isinstance(cape_report, dict):
            errors.append(
                _error("/", f"report phải là object, nhận {_type_name(cape_report)}")
            )
            return

        behavior = cape_report.get("behavior")
        if behavior is None:
            errors.append(_error("/behavior", "thiếu object 'behavior' bắt buộc"))
            return
        if not isinstance(behavior, dict):
            errors.append(
                _error("/behavior", f"phải là object, nhận {_type_name(behavior)}")
            )
            return

        processes = behavior.get("processes")
        if processes is None:
            errors.append(
                _error("/behavior/processes", "thiếu mảng 'processes' bắt buộc")
            )
            return
        if not isinstance(processes, list):
            errors.append(
                _error(
                    "/behavior/processes",
                    f"phải là mảng, nhận {_type_name(processes)}",
                )
            )
            return

        for proc_idx, process in enumerate(processes):
            proc_path = f"/behavior/processes/{proc_idx}"
            if not isinstance(process, dict):
                errors.append(
                    _error(
                        proc_path,
                        f"phần tử process phải là object, nhận {_type_name(process)}",
                    )
                )
                continue
            pid = self._process_id(process, proc_path, errors)

            calls = process.get("calls")
            if calls is None:
                errors.append(
                    _error(f"{proc_path}/calls", "thiếu mảng 'calls' bắt buộc")
                )
                continue
            if not isinstance(calls, list):
                errors.append(
                    _error(
                        f"{proc_path}/calls",
                        f"phải là mảng, nhận {_type_name(calls)}",
                    )
                )
                continue

            for call_idx, call in enumerate(calls):
                yield from self._iter_call(
                    call, proc_idx, call_idx, proc_path, pid, errors
                )

    def _iter_call(
        self,
        call: object,
        proc_idx: int,
        call_idx: int,
        proc_path: str,
        pid: str,
        errors: list[TelemetryError],
    ) -> Iterator[TelemetryString]:
        call_path = f"{proc_path}/calls/{call_idx}"
        if not isinstance(call, dict):
            errors.append(
                _error(
                    call_path,
                    f"phần tử call phải là object, nhận {_type_name(call)}",
                )
            )
            return

        api = call.get("api")
        if not isinstance(api, str):
            errors.append(
                _error(
                    f"{call_path}/api",
                    f"thiếu 'api' hoặc sai kiểu, nhận {_type_name(api)}",
                )
            )
            return

        allowed_args = self.TEXT_ARG_ALLOWLIST.get(api)
        if allowed_args is None:
            return

        timestamp = call.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, str):
            errors.append(
                _error(
                    f"{call_path}/timestamp",
                    f"'timestamp' sai kiểu, nhận {_type_name(timestamp)}",
                )
            )
            timestamp = None

        arguments = call.get("arguments")
        if arguments is None:
            errors.append(
                _error(f"{call_path}/arguments", "thiếu mảng 'arguments' bắt buộc")
            )
            return
        if not isinstance(arguments, list):
            errors.append(
                _error(
                    f"{call_path}/arguments",
                    f"phải là mảng, nhận {_type_name(arguments)}",
                )
            )
            return

        for arg_idx, argument in enumerate(arguments):
            arg_path = f"{call_path}/arguments/{arg_idx}"
            if not isinstance(argument, dict):
                errors.append(
                    _error(
                        arg_path,
                        f"phần tử argument phải là object, nhận "
                        f"{_type_name(argument)}",
                    )
                )
                continue
            name = argument.get("name")
            if not isinstance(name, str):
                errors.append(
                    _error(
                        f"{arg_path}/name",
                        f"thiếu 'name' hoặc sai kiểu, nhận {_type_name(name)}",
                    )
                )
                continue
            if name not in allowed_args:
                continue
            value = argument.get("value")
            if not isinstance(value, str):
                errors.append(
                    _error(
                        f"{arg_path}/value",
                        f"thiếu 'value' hoặc sai kiểu, nhận {_type_name(value)}",
                    )
                )
                continue
            if len(value) < _MIN_VALUE_LENGTH or value.startswith(_HEX_PREFIX):
                continue

            yield TelemetryString(
                raw_string=value,
                provenance=Provenance(
                    type=ProvenanceType.JSON_LOG_POINTER,
                    locator=(
                        f"/behavior/processes/{proc_idx}/calls/{call_idx}"
                        f"/arguments/{arg_idx}"
                    ),
                    section_or_pid=pid,
                ),
                api=api,
                timestamp=timestamp,
            )

    @staticmethod
    def _process_id(
        process: dict, proc_path: str, errors: list[TelemetryError]
    ) -> str:
        raw_pid = process.get("process_id")
        if raw_pid is None:
            return "unknown"
        if isinstance(raw_pid, bool) or not isinstance(raw_pid, (int, str)):
            errors.append(
                _error(
                    f"{proc_path}/process_id",
                    f"'process_id' sai kiểu, nhận {_type_name(raw_pid)}",
                )
            )
            return "unknown"
        return str(raw_pid)
