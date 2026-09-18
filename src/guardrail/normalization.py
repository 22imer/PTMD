"""Lớp 0 — Normalization & De-obfuscation Engine (spec v1.4.0 §3.1).

Vô hiệu hoá kỹ thuật làm rối chuỗi trước khi dữ liệu trích xuất đi vào YARA và
mô hình ML. Engine thao tác trên **bản sao** chuỗi (`raw_string`), không chạm
tệp PE gốc, và giữ nguyên `Provenance` đầu vào (contract §4.1,
`guardrail.contracts.Provenance`) để truy vết nguồn.

Thứ tự biến đổi giữ đúng spec §3.1:

1. `STRIP_ZERO_WIDTH` — xoá zero-width/NBSP `[\\u200B-\\u200D\\uFEFF\\u00A0]`.
2. `UNICODE_NFKD` — phân rã tương thích NFKD (fullwidth, ligature, dấu tổ hợp).
3. `HOMOGLYPH_RESOLVE` — thay ký tự nhìn giống Latin (Cyrillic/Greek/...) bằng
   ASCII theo `confusables_map`.
4. `DECODE_RECURSIVE_D{n}` — giải mã Base64 (ưu tiên) rồi Hex, tối đa
   `MAX_DECODING_DEPTH` tầng, chỉ khi độ dài byte UTF-8 của văn bản hiện tại
   không vượt `MAX_DECODE_INPUT_BYTES`, kết quả ≥ `MIN_DECODED_LENGTH` ký tự và
   tỉ lệ ký tự in được ≥ `MIN_PRINTABLE_RATIO`.

`transform_chain` **cộng dồn qua mọi tầng đệ quy**: mỗi lời gọi đệ quy nhận
`prior_transforms` của tầng trước, nên vết trả về bao gồm cả các bước biến đổi ở
tầng ngoài, không chỉ tầng giải mã cuối cùng.

**Giới hạn đã biết (giữ nguyên theo spec §3.1, không tự sửa):** vì Base64 được
thử trước Hex và `BASE64_REGEX` chỉ kiểm alphabet/độ dài, một chuỗi Hex có độ dài
chia hết cho 4 (ví dụ 16/20 ký tự hex) cũng khớp Base64 và sẽ bị giải mã theo
Base64 — kết quả là rác in được thay vì bản Hex đúng. Các case 1 tầng không bị
ảnh hưởng; case lồng nhau cần tầng trong có độ dài hex không chia hết cho 4 mới
được giải mã đúng. Việc phân xử Base64/Hex là hạng mục cần chốt ở Phase 0 (R01),
không nằm trong phạm vi T03.
"""

from __future__ import annotations

import base64
import json
import re
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple, Optional

from guardrail.contracts import Provenance

__all__ = [
    "CONFUSABLES_PATH",
    "MAX_DECODING_DEPTH",
    "MAX_DECODE_INPUT_BYTES",
    "MIN_DECODED_LENGTH",
    "MIN_PRINTABLE_RATIO",
    "NormalizationEngine",
    "NormalizedText",
    "load_confusables_map",
]

#: Ngân sách byte UTF-8 tối đa của văn bản được phép thử giải mã (spec §3.1).
MAX_DECODE_INPUT_BYTES = 65536
#: Số tầng giải mã đệ quy tối đa (spec §3.1).
MAX_DECODING_DEPTH = 2
#: Kết quả giải mã ngắn hơn ngưỡng này bị coi là nhiễu, không nhận (spec §3.1).
MIN_DECODED_LENGTH = 4
#: Tỉ lệ ký tự in được tối thiểu để nhận kết quả giải mã (spec §3.1).
MIN_PRINTABLE_RATIO = 0.80

#: Vị trí bảng confusables mặc định (subset UTS #39 rút gọn).
CONFUSABLES_PATH = Path(__file__).with_name("data") / "confusables_min.json"


class NormalizedText(NamedTuple):
    """Kết quả chuẩn hoá (spec §3.1).

    `provenance` là **chính đối tượng** được truyền vào `NormalizationEngine.normalize`
    (không sao chép) nên vẫn dùng được trực tiếp cho `provenance` của
    `EvidenceRecord` (schema §4.1).
    """

    normalized_string: str
    provenance: Provenance
    decoding_depth: int
    transform_chain: list[str]


def load_confusables_map(path: str | Path | None = None) -> dict[str, str]:
    """Nạp bảng confusables từ JSON (mặc định `guardrail/data/confusables_min.json`).

    File dữ liệu có metadata (`source`, `version`, `note`, `entry_count`) và map
    `confusables` gồm các cặp `ký_tự_1_byte_ký_tự` -> `ASCII`. Sai cấu trúc →
    `ValueError` (bảng hỏng sẽ âm thầm làm sai kết quả chuẩn hoá nên bị chặn sớm).
    """
    data = json.loads(Path(path or CONFUSABLES_PATH).read_text(encoding="utf-8"))
    entries = data["confusables"]
    for source, target in entries.items():
        if len(source) != 1 or len(target) != 1 or not target.isascii() or not target.isprintable():
            raise ValueError(f"cặp confusable không hợp lệ: {source!r} -> {target!r}")
    return dict(entries)


class NormalizationEngine:
    """Chuẩn hoá chuỗi trích xuất theo spec §3.1.

    `confusables_map` được truyền từ ngoài (spec §3.1); dùng
    `load_confusables_map()` để lấy subset mặc định của repo.
    """

    ZERO_WIDTH_REGEX = re.compile(r"[\u200B-\u200D\uFEFF\u00A0]")
    BASE64_REGEX = re.compile(r"^[A-Za-z0-9+/=]{16,}$")
    HEX_REGEX = re.compile(r"^(?:[0-9a-fA-F]{2}){8,}$")

    def __init__(self, confusables_map: Mapping[str, str]) -> None:
        self.confusables_map = confusables_map

    def normalize(
        self,
        raw_string: str,
        provenance: Provenance,
        depth: int = 0,
        prior_transforms: Optional[list[str]] = None,
    ) -> NormalizedText:
        """Chuẩn hoá `raw_string` và trả `NormalizedText` giữ nguyên `provenance`.

        `depth` và `prior_transforms` là tham số đệ quy; gọi từ ngoài chỉ cần hai
        tham số đầu. `depth` là số tầng giải mã đã thực hiện, `prior_transforms`
        là vết biến đổi tích luỹ từ các tầng ngoài.
        """
        if not isinstance(raw_string, str):
            raise TypeError(f"raw_string phải là str, nhận {type(raw_string).__name__}")

        transforms = list(prior_transforms) if prior_transforms else []
        text = raw_string

        # 1. Zero-width stripping
        if self.ZERO_WIDTH_REGEX.search(text):
            text = self.ZERO_WIDTH_REGEX.sub("", text)
            transforms.append("STRIP_ZERO_WIDTH")

        # 2. Unicode NFKD decomposition
        text_decomposed = unicodedata.normalize("NFKD", text)
        if text_decomposed != text:
            text = text_decomposed
            transforms.append("UNICODE_NFKD")

        # 3. Homoglyph resolution
        text_homo = "".join(self.confusables_map.get(char, char) for char in text)
        if text_homo != text:
            text = text_homo
            transforms.append("HOMOGLYPH_RESOLVE")

        # 4. Bounded recursive decoding (Base64 trước, rồi Hex; ngân sách byte UTF-8)
        # `surrogatepass`: ngân sách tính trên byte UTF-8 như spec §3.1, nhưng chuỗi
        # chứa lone surrogate (ví dụ giá trị JSON escape "\ud800" từ report CAPEv2)
        # vẫn phải đo được thay vì ném UnicodeEncodeError.
        if (
            depth < MAX_DECODING_DEPTH
            and len(text.encode("utf-8", "surrogatepass")) <= MAX_DECODE_INPUT_BYTES
        ):
            decoded = self._try_decode(text)
            if decoded is not None and self._is_mostly_printable(decoded):
                transforms.append(f"DECODE_RECURSIVE_D{depth + 1}")
                return self.normalize(decoded, provenance, depth + 1, prior_transforms=transforms)

        return NormalizedText(text, provenance, depth, transforms)

    def _is_mostly_printable(self, s: str) -> bool:
        """True nếu tỉ lệ ký tự in được (kể cả `\\r\\n\\t`) đạt `MIN_PRINTABLE_RATIO`."""
        printable = sum(1 for char in s if char.isprintable() or char in "\r\n\t")
        return (printable / max(len(s), 1)) >= MIN_PRINTABLE_RATIO

    def _try_decode(self, s: str) -> Optional[str]:
        """Giải mã Base64 (ưu tiên) rồi Hex; None nếu không khớp/không đủ dài."""
        stripped = s.strip()
        if self.BASE64_REGEX.match(stripped):
            try:
                res = base64.b64decode(stripped, validate=True).decode("utf-8", errors="ignore")
                if len(res) >= MIN_DECODED_LENGTH:
                    return res
            except Exception:
                pass
        if self.HEX_REGEX.match(stripped):
            try:
                res = bytes.fromhex(stripped).decode("utf-8", errors="ignore")
                if len(res) >= MIN_DECODED_LENGTH:
                    return res
            except Exception:
                pass
        return None
