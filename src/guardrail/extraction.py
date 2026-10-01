"""Trích xuất chuỗi tĩnh từ bytes (T02, spec v1.4.0 §3.2.1).

Module này là phần đầu của **pha trích xuất**: biến một artifact bytes (mẫu PE
nạp từ đĩa) thành ``RawString`` bản sao kèm ``Provenance`` kiểu ``FILE_OFFSET``.
Kết quả đi tiếp vào Normalization (Lớp 0) rồi Detector — không đưa text trích
xuất thẳng vào Agent (spec §2, contract T00 "Extraction → Module 0").

Ràng buộc lấy nguyên từ spec §3.2.1:

- Trích chuỗi ASCII và UTF-16LE, độ dài **6–256 ký tự**.
- Tối đa **2.000 chuỗi/mẫu**; chạm trần thì ghi coverage ``PARTIAL``
  (``TRUNCATED_ARTIFACT_FLAG`` ở tầng policy) thay vì im lặng coi là ``COMPLETE``.
- Lọc theo Shannon entropy trong **[2.5, 5.5]**.
- (Tuỳ chọn) ``sections`` để ưu tiên ``.rsrc``/``.data``/Export-Import/Debug
  theo spec §3.2.1; không truyền thì quét phẳng toàn artifact.

Ngoài phạm vi (không tự suy diễn): artifact memory dump. Provenance
``VIRTUAL_ADDRESS`` cần metadata nguồn đã xác nhận (hash mẫu gốc, VA map) do
PE-sieve cung cấp ở pha trích xuất; module này **không** suy ra địa chỉ ảo từ
offset trong dump (checklist T02: "không tự suy ra địa chỉ từ dump offset").

Chuỗi dài hơn 256 ký tự bị cắt thành các đoạn liên tiếp ≤256 ký tự, mỗi đoạn
giữ offset riêng, để không mất dữ liệu vì giới hạn độ dài.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterator, Sequence
from typing import NamedTuple, TypedDict

from guardrail.contracts import ProcessingState, Provenance, ProvenanceType

__all__ = [
    "ENCODING_ASCII",
    "ENCODING_UTF16LE",
    "ExtractedString",
    "ExtractionResult",
    "MAX_ENTROPY",
    "MAX_STRING_LENGTH",
    "MAX_STRINGS",
    "MIN_ENTROPY",
    "MIN_STRING_LENGTH",
    "PRIORITY_SECTION_NAMES",
    "RawString",
    "extract_strings",
    "shannon_entropy",
]

# --- Giới hạn trích xuất (spec §3.2.1) ------------------------------------

MIN_STRING_LENGTH = 6
MAX_STRING_LENGTH = 256
MAX_STRINGS = 2000
MIN_ENTROPY = 2.5
MAX_ENTROPY = 5.5

#: Byte ASCII in được (0x20–0x7E) — dùng cho cả chuỗi ASCII và code unit UTF-16LE.
_PRINTABLE_ASCII = frozenset(range(0x20, 0x7F))

ENCODING_ASCII = "ASCII"
ENCODING_UTF16LE = "UTF-16LE"
_ENCODING_WIDTH = {ENCODING_ASCII: 1, ENCODING_UTF16LE: 2}

#: Vùng ưu tiên theo spec §3.2.1. Export/Import table và Debug directory nằm ở
#: các section quy ước ``.edata``/``.idata``/``.debug`` trong PE Windows.
PRIORITY_SECTION_NAMES = (".rsrc", ".data", ".edata", ".idata", ".debug")

_FLAT_LABEL = "<flat>"

#: Một section do caller cung cấp: ``(name, offset, size)``.
SectionSpec = tuple[str, int, int]


class RawString(TypedDict):
    """Kernel dùng chung của pha trích xuất: chuỗi bản sao + provenance.

    Contract T00 "Extraction → Module 0": chuỗi bản sao + ``provenance`` với
    ``type``/``locator``/``section_or_pid``. Telemetry adapter tái dùng kiểu này.
    """

    raw_string: str
    provenance: Provenance


class ExtractedString(RawString):
    """``RawString`` tĩnh kèm ``encoding`` nguồn (``ASCII`` | ``UTF-16LE``)."""

    encoding: str


class ExtractionResult(NamedTuple):
    """Kết quả trích xuất + coverage của lần quét.

    ``coverage`` là ``ProcessingState.COMPLETE`` khi quét hết ngân sách, và
    ``ProcessingState.PARTIAL`` khi chạm trần 2.000 chuỗi (dữ liệu còn lại bị bỏ).
    """

    strings: list[ExtractedString]
    coverage: ProcessingState
    scanned_sections: list[str]


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bit/ký tự) của ``text``; chuỗi rỗng trả 0.0."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(text).values()
    )


def _iter_ascii_runs(data: bytes) -> Iterator[tuple[int, str]]:
    """Sinh ``(offset, text)`` cho mọi run byte ASCII in được liên tiếp."""
    length = len(data)
    index = 0
    while index < length:
        if data[index] in _PRINTABLE_ASCII:
            end = index
            while end < length and data[end] in _PRINTABLE_ASCII:
                end += 1
            yield index, data[index:end].decode("ascii")
            index = end
        else:
            index += 1


def _iter_utf16le_runs(data: bytes) -> Iterator[tuple[int, str]]:
    """Sinh ``(offset, text)`` cho mọi run code unit UTF-16LE in được.

    Chỉ nhận code unit ASCII in được (0x20–0x7E): đủ cho "chuỗi UTF-16LE" mà
    spec §3.2.1 nhắc tới, và tránh nhận nhầm cặp byte nhị phân thành chữ.
    """
    length = len(data)
    index = 0
    while index + 1 < length:
        unit = data[index] | (data[index + 1] << 8)
        if unit in _PRINTABLE_ASCII:
            start = index
            chars: list[str] = []
            while index + 1 < length:
                current = data[index] | (data[index + 1] << 8)
                if current not in _PRINTABLE_ASCII:
                    break
                chars.append(chr(current))
                index += 2
            yield start, "".join(chars)
        else:
            index += 1


def _candidates(data: bytes) -> list[tuple[int, str, str]]:
    """Gộp run ASCII + UTF-16LE của một vùng, sắp theo offset."""
    merged: list[tuple[int, str, str]] = [
        (offset, text, ENCODING_ASCII) for offset, text in _iter_ascii_runs(data)
    ]
    merged.extend(
        (offset, text, ENCODING_UTF16LE) for offset, text in _iter_utf16le_runs(data)
    )
    merged.sort(key=lambda item: item[0])
    return merged


def _iter_region_strings(payload: bytes) -> Iterator[tuple[int, str, str]]:
    """Sinh ``(offset_tương_đối, chuỗi, encoding)`` đã cắt đoạn + lọc entropy."""
    for offset, text, encoding in _candidates(payload):
        width = _ENCODING_WIDTH[encoding]
        for start in range(0, len(text), MAX_STRING_LENGTH):
            chunk = text[start : start + MAX_STRING_LENGTH]
            if len(chunk) < MIN_STRING_LENGTH:
                continue
            if not MIN_ENTROPY <= shannon_entropy(chunk) <= MAX_ENTROPY:
                continue
            yield offset + start * width, chunk, encoding


def _build_regions(
    data: bytes, sections: Sequence[SectionSpec] | None
) -> list[tuple[str | None, int, bytes]]:
    """Dựng danh sách vùng quét ``(tên_section, offset_tuyệt_đối, payload)``.

    Vùng ưu tiên (``PRIORITY_SECTION_NAMES``) xếp trước, giữ nguyên thứ tự
    tương đối trong từng nhóm. Khi không có ``sections`` thì quét phẳng toàn bộ
    ``data`` với ``section_or_pid=None``.
    """
    if not sections:
        return [(None, 0, data)]
    ordered = sorted(sections, key=lambda section: section[0] not in PRIORITY_SECTION_NAMES)
    regions: list[tuple[str | None, int, bytes]] = []
    for name, offset, size in ordered:
        start = max(0, offset)
        end = min(len(data), start + max(0, size))
        if end <= start:
            continue
        regions.append((name, start, data[start:end]))
    return regions


def extract_strings(
    data: bytes, sections: Sequence[SectionSpec] | None = None
) -> ExtractionResult:
    """Trích chuỗi ASCII/UTF-16LE từ ``data`` theo spec §3.2.1.

    Args:
        data: nội dung artifact thô (bytes-like).
        sections: tuỳ chọn ``[(name, offset, size), ...]`` của các section PE.
            Khi cung cấp, chỉ quét các vùng này và ưu tiên theo
            ``PRIORITY_SECTION_NAMES``; offset trong ``locator`` là offset tuyệt
            đối trong artifact và ``section_or_pid`` là tên section.

    Returns:
        ``ExtractionResult`` với chuỗi kèm provenance ``FILE_OFFSET`` và cờ
        coverage (``COMPLETE``/``PARTIAL``).

    Raises:
        TypeError: nếu ``data`` không phải bytes-like.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data phải là bytes-like, nhận {type(data).__name__}")
    payload_bytes = bytes(data)

    strings: list[ExtractedString] = []
    scanned_sections: list[str] = []
    truncated = False

    for name, base_offset, payload in _build_regions(payload_bytes, sections):
        scanned_sections.append(name if name is not None else _FLAT_LABEL)
        for offset, text, encoding in _iter_region_strings(payload):
            if len(strings) >= MAX_STRINGS:
                truncated = True
                break
            strings.append(
                ExtractedString(
                    raw_string=text,
                    provenance=Provenance(
                        type=ProvenanceType.FILE_OFFSET,
                        locator=f"0x{base_offset + offset:08X}",
                        section_or_pid=name,
                    ),
                    encoding=encoding,
                )
            )
        if truncated:
            break

    coverage = ProcessingState.PARTIAL if truncated else ProcessingState.COMPLETE
    return ExtractionResult(strings, coverage, scanned_sections)
