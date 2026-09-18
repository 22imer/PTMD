"""Tests cho module trích xuất tĩnh (T02, spec §3.2.1).

Dữ liệu test là synthetic/vô hại. Golden assertions theo giới hạn spec: dài
6–256, tối đa 2.000 chuỗi, entropy [2.5, 5.5], provenance FILE_OFFSET, và cờ
coverage khi chạm trần.
"""

from __future__ import annotations

import math

import pytest

from guardrail.contracts import ProcessingState, ProvenanceType
from guardrail.extraction import (
    ENCODING_ASCII,
    ENCODING_UTF16LE,
    MAX_ENTROPY,
    MAX_STRING_LENGTH,
    MAX_STRINGS,
    MIN_ENTROPY,
    PRIORITY_SECTION_NAMES,
    extract_strings,
    shannon_entropy,
)


def _raw(result) -> list[str]:
    return [item["raw_string"] for item in result.strings]


def test_empty_input_returns_complete_and_empty() -> None:
    result = extract_strings(b"")

    assert result.strings == []
    assert result.coverage is ProcessingState.COMPLETE
    assert result.scanned_sections == ["<flat>"]


def test_non_bytes_input_rejected() -> None:
    with pytest.raises(TypeError):
        extract_strings("not bytes")  # type: ignore[arg-type]


def test_ascii_string_carries_file_offset_provenance() -> None:
    data = b"\x00\x00\x00" + b"hello_world_payload" + b"\x00\x00"

    result = extract_strings(data)

    assert len(result.strings) == 1
    item = result.strings[0]
    assert item["raw_string"] == "hello_world_payload"
    assert item["encoding"] == ENCODING_ASCII
    assert item["provenance"] == {
        "type": ProvenanceType.FILE_OFFSET,
        "locator": "0x00000003",
        "section_or_pid": None,
    }
    assert result.coverage is ProcessingState.COMPLETE


def test_utf16le_string_extracted_with_correct_offset() -> None:
    wide = "Wide UTF16 payload".encode("utf-16-le")
    data = b"\x00\x00" + wide + b"\x00\x00"

    result = extract_strings(data)

    assert len(result.strings) == 1
    item = result.strings[0]
    assert item["raw_string"] == "Wide UTF16 payload"
    assert item["encoding"] == ENCODING_UTF16LE
    assert item["provenance"]["locator"] == "0x00000002"


def test_ascii_and_utf16le_interleaved_sorted_by_offset() -> None:
    ascii_blob = b"ascii_payload_here"
    wide_blob = "wide_payload_here".encode("utf-16-le")
    data = ascii_blob + b"\x00\x00" + wide_blob

    result = extract_strings(data)

    assert [item["encoding"] for item in result.strings] == [
        ENCODING_ASCII,
        ENCODING_UTF16LE,
    ]
    assert [item["provenance"]["locator"] for item in result.strings] == [
        "0x00000000",
        f"0x{len(ascii_blob) + 2:08X}",
    ]


def test_length_bounds_minimum_drops_short_runs() -> None:
    data = b"abcde\x00abcdef\x00"

    result = extract_strings(data)

    assert _raw(result) == ["abcdef"]


def test_long_run_split_into_bounded_chunks() -> None:
    long_text = "abcdefghij" * 30  # 300 ký tự, entropy log2(10) ≈ 3.32
    assert len(long_text) == 300

    result = extract_strings(long_text.encode("ascii"))

    assert [len(item["raw_string"]) for item in result.strings] == [
        MAX_STRING_LENGTH,
        300 - MAX_STRING_LENGTH,
    ]
    assert result.strings[0]["raw_string"] == long_text[:MAX_STRING_LENGTH]
    assert result.strings[1]["raw_string"] == long_text[MAX_STRING_LENGTH:]
    assert [item["provenance"]["locator"] for item in result.strings] == [
        "0x00000000",
        f"0x{MAX_STRING_LENGTH:08X}",
    ]


def test_shannon_entropy_known_values() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("AAAAAA") == pytest.approx(0.0)
    assert shannon_entropy("ababab") == pytest.approx(1.0)
    assert shannon_entropy("abcdef") == pytest.approx(math.log2(6))


def test_entropy_boundaries_filter_low_and_high() -> None:
    low_entropy = b"AAAAAA\x00ababab"  # H = 0.0 và 1.0 → dưới MIN_ENTROPY
    within = b"\x00abcdef\x00"  # H = log2(6) ≈ 2.585 ∈ [2.5, 5.5]
    high_entropy = "".join(chr(0x21 + index % 94) for index in range(200))
    assert shannon_entropy(high_entropy) > MAX_ENTROPY

    low_result = extract_strings(low_entropy)
    assert _raw(low_result) == []

    within_result = extract_strings(within)
    assert _raw(within_result) == ["abcdef"]
    assert MIN_ENTROPY <= shannon_entropy("abcdef") <= MAX_ENTROPY

    high_result = extract_strings(high_entropy.encode("ascii"))
    assert _raw(high_result) == []


def test_sections_prioritised_and_locator_is_absolute() -> None:
    data = bytearray(b"\x00" * 256)
    text_blob = b"TEXT_SECTION_PAYLOAD"
    data_blob = b"DATA_SECTION_PAYLOAD"
    data[0 : len(text_blob)] = text_blob
    data[128 : 128 + len(data_blob)] = data_blob

    result = extract_strings(
        bytes(data),
        [(".text", 0, 128), (".data", 128, 128)],
    )

    assert _raw(result) == ["DATA_SECTION_PAYLOAD", "TEXT_SECTION_PAYLOAD"]
    assert result.scanned_sections == [".data", ".text"]
    assert result.strings[0]["provenance"] == {
        "type": ProvenanceType.FILE_OFFSET,
        "locator": "0x00000080",
        "section_or_pid": ".data",
    }
    assert result.strings[1]["provenance"]["locator"] == "0x00000000"
    assert result.strings[1]["provenance"]["section_or_pid"] == ".text"
    assert ".rsrc" in PRIORITY_SECTION_NAMES and ".data" in PRIORITY_SECTION_NAMES


def test_sections_out_of_bounds_are_clamped() -> None:
    data = b"CLAMPED_PAYLOAD_DATA" + b"\x00" * 8

    result = extract_strings(data, [(".data", 0, 9999), (".rsrc", 5000, 10)])

    assert _raw(result) == ["CLAMPED_PAYLOAD_DATA"]
    assert result.scanned_sections == [".data"]


def test_budget_exceeded_reports_partial_coverage() -> None:
    runs = [f"payload_string_{index:05d}".encode("ascii") for index in range(MAX_STRINGS + 5)]
    data = b"\x00".join(runs)

    result = extract_strings(data)

    assert len(result.strings) == MAX_STRINGS
    assert result.coverage is ProcessingState.PARTIAL
    assert result.strings[0]["raw_string"] == "payload_string_00000"
    assert result.strings[-1]["raw_string"] == f"payload_string_{MAX_STRINGS - 1:05d}"


def test_exactly_budget_strings_is_complete() -> None:
    runs = [f"payload_string_{index:05d}".encode("ascii") for index in range(MAX_STRINGS)]
    data = b"\x00".join(runs)

    result = extract_strings(data)

    assert len(result.strings) == MAX_STRINGS
    assert result.coverage is ProcessingState.COMPLETE
