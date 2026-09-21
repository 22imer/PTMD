"""YARA Static / Memory / Cuckoo Scanner — Lớp 1 (T04, spec v1.4.0 §2, §3.2).

Module này áp ruleset YARA lên ba loại input mà spec §2 (khối "LỚP 1") nêu:
file tĩnh trên đĩa, memory dump từ PE-sieve, và report hành vi CAPEv2 qua module
Cuckoo. Nó là detector, không phải policy: output là ``Finding`` + lỗi/coverage,
đúng contract T00 "Detector → Policy" (``implemention.md`` §3, hàng "Detector → Policy"): finding giữg giữ
artifact/provenance, detector name/version, transform chain; **processing state
độc lập detection state và lỗi detector không bị đổi thành NOT_DETECTED**.

Ba đường quét, cùng một ruleset tĩnh ``rules/promptware.yar``:

- ``scan_bytes`` — quét bytes thô (file PE hoặc memory dump). Offset trong
  ``Finding.matched_offsets`` là offset byte **trong chính artifact được đưa
  vào**; ``detection_source`` do caller khai (``STATIC_STRING`` cho file,
  ``DYNAMIC_MEMORY_DUMP`` cho memory dump). Scanner không tự suy địa chỉ ảo từ
  offset dump (spec §3.2.2; ``implemention.md`` §4 T02): muốn provenancence
  ``VIRTUAL_ADDRESS`` thì caller truyền ``provenance`` đã xác nhận.
- ``scan_text`` / ``scan_normalized`` — quét từng chuỗi đã chuẩn hoá của Lớp 0.
  Ở mức chuỗi, offset byte không có nghĩa (bản chuẩn hoá đã bị biến đổi), nên
  ``matched_offsets``/``matched_data`` để rỗng và **provenance của caller được
  giữ nguyên** (cùng đối tượng ``Provenance`` mà ``NormalizationEngine`` trả về),
  kèm ``transform_chain`` để truy vết. Không lấy offset của chuỗi normalized
  làm file offset (``implemention.md`` §4 T04).).
- ``scan_cape_report`` — quét report CAPEv2 bằng module Cuckoo qua **module-data**
  ``modules_data={"cuckoo": <bytes report>}`` (cùng kênh với CLI
  ``-x cuckoo=<report>`` ≡ ``--module-data``; errata SP-01 trong
  ``issues/issue_2026-09-20_full_project_review_new_findings.md``). Đây là cơ chế **độc
  lập** với Telemetry Ingestion Adapter (T02): adapter trích API arguments
  (``OutputDebugString``/``SetWindowText``/``MessageBox``) thành ``RawString``
  cho scanner chuỗi, còn module Cuckoo kiểm tra network/file/registry/mutex
  trong chính report — hai cơ chế không thay thế nhau.

Module Cuckoo không khả dụng (build thiếu ``--enable-cuckoo``)
--------------------------------------------------------------
``probe_cuckoo_capability()`` biên dịch một rule tối thiểu ``import "cuckoo"``.
Build thiếu module trả ``unknown module "cuckoo"`` ⇒ capability
``available=False``, ``flag="cuckoo_unavailable"`` và scanner Cuckoo **bị vô
hiệu, không thay thế bằng cơ chế ngầm** (spec §3.2.2). ``scan_cape_report`` khi
đó trả một ``ScanError`` kind ``CAPABILITY`` kèm ``coverage=PARTIAL`` — không
bao giờ trả "không có finding" trần trụi, vì coverage gap ≠ verdict vô hại.

Contract lỗi & coverage
-----------------------
Theo convention của ``telemetry.py``: lỗi cấu trúc/môi trường thành phần tử
``ScanError`` (``kind`` + ``path`` + ``reason``) trong ``ScanResult.errors``,
không crash và không bị hạ thành "không phát hiện".

- ``coverage=COMPLETE`` — ruleset biên dịch được và lần quét kết thúc không lỗi
  (kể cả khi ``findings`` rỗng: vô hại thật sự).
- ``coverage=PARTIAL`` — lần quét chạy nhưng có lỗi giữa đường (scan error,
  Cuckoo không khả dụng); finding đã phát hiện **trước** lỗi vẫn được giữ.
- ``coverage=FAILED`` — ruleset không đọc được hoặc biên dịch lỗi, nên không có
  finding nào được tạo ra một cách đáng tin cậy.

``YaraScanner.manifest()`` trả build/ruleset hash để log kèm kết quả
(``implemention.md`` §4 T04 Nghiệm thu: "Log ghi build/ruleset/fixture hash")..

Chỉ dùng stdlib + ``yara-python``; không chạy sample, không điều khiển sandbox,
không gắn vào PID sống.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import NamedTuple, TypedDict

import yara

from guardrail.contracts import (
    DetectionSource,
    DetectorName,
    ProcessingState,
    Provenance,
)
from guardrail.normalization import NormalizedText

__all__ = [
    "CUCKOO_UNAVAILABLE_FLAG",
    "DEFAULT_CUCKOO_RULES_PATH",
    "DEFAULT_RULES_PATH",
    "CuckooCapability",
    "CuckooScanResult",
    "Finding",
    "RulesetOutcome",
    "ScanError",
    "ScanErrorKind",
    "ScanResult",
    "YaraScanner",
    "compile_ruleset",
    "probe_cuckoo_capability",
]

#: Ruleset tĩnh (spec §3.2.1) — luôn biên dịch được, không import module.
DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "promptware.yar"
#: Ruleset Cuckoo (spec §3.2.2) — chỉ biên dịch được khi build có ``--enable-cuckoo``.
DEFAULT_CUCKOO_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "rules" / "promptware_cuckoo.yar"
)

#: Cờ cấu hình ghi khi scanner Cuckoo bị vô hiệu (spec §3.2.2).
CUCKOO_UNAVAILABLE_FLAG = "cuckoo_unavailable"

#: Rule tối thiểu để thăm dò module Cuckoo; đúng chuỗi lỗi ``unknown module "cuckoo"``.
_CUCKOO_PROBE_SOURCE = 'import "cuckoo"\nrule __cuckoo_probe { condition: true }\n'

_MITRE_ATLAS_META = "mitre_atlas"
_VERSION_META = "version"


class ScanErrorKind(StrEnum):
    """Loại lỗi của một lần compile/scan (mỗi loại map tới một nhánh coverage)."""

    RULESET_READ = "RULESET_READ"
    COMPILE_ERROR = "COMPILE_ERROR"
    SCAN_ERROR = "SCAN_ERROR"
    CAPABILITY = "CAPABILITY"


class ScanError(TypedDict):
    """Một lỗi môi trường/cấu trúc: ``kind``, ``path`` (ruleset/report/artifact) và ``reason``."""

    kind: ScanErrorKind
    path: str
    reason: str


class CuckooCapability(NamedTuple):
    """Kết quả thăm dò module Cuckoo của build YARA đang dùng.

    ``available=False`` ⇒ ``flag`` là :data:`CUCKOO_UNAVAILABLE_FLAG` và
    ``reason`` là thông điệp compile thật (kỳ vọng ``unknown module "cuckoo"``).
    ``available=True`` ⇒ ``flag=None``, ``reason=""``.
    """

    available: bool
    flag: str | None
    reason: str
    yara_version: str


class RulesetOutcome(NamedTuple):
    """Kết quả biên dịch một file ruleset.

    ``rules`` là ``None`` khi ``errors`` khác rỗng; ``rules_sha256`` là hash file
    luật tại thời điểm nạp (``None`` nếu không đọc được file).
    """

    rules: yara.Rules | None
    errors: list[ScanError]
    coverage: ProcessingState
    rules_sha256: str | None


class Finding(NamedTuple):
    """Một rule khớp: detector/rule identity + bằng chứng + đường truy vết.

    - ``detector_name`` — ``YARA_STATIC`` (ruleset ``promptware.yar``) hoặc
      ``YARA_CUCKOO`` (ruleset ``promptware_cuckoo.yar``).
    - ``rule`` / ``tags`` / ``meta`` — nguyên văn từ match; ``mitre_atlas`` và
      ``rule_version`` tiện ra sẵn từ meta (``None`` nếu rule không khai).
    - ``matched_identifiers`` — tên các string của rule đã khớp (``$override_1``…).
    - ``matched_offsets`` / ``matched_data`` — **chỉ** có giá trị khi quét bytes
      (offset byte artifact + bytes khớp); quét mức chuỗi để rỗng vì bản
      normalized không còn giữ vị trí gốc.
    - ``detection_source`` — caller khai nguồn artifact (spec §4.1).
    - ``provenance`` — provenance của caller, giữ nguyên đối tượng (``None`` với
      bytes scan không kèm provenance).
    - ``transform_chain`` — vết biến đổi của ``NormalizedText`` (rỗng với bytes).
    """

    detector_name: DetectorName
    rule: str
    tags: list[str]
    meta: dict[str, object]
    mitre_atlas: str | None
    rule_version: str | None
    matched_identifiers: list[str]
    matched_offsets: list[int]
    matched_data: list[bytes]
    detection_source: DetectionSource
    provenance: Provenance | None
    transform_chain: list[str]


class ScanResult(NamedTuple):
    """Kết quả ``scan_bytes``/``scan_text``/``scan_normalized``: findings + lỗi + coverage."""

    findings: list[Finding]
    errors: list[ScanError]
    coverage: ProcessingState


class CuckooScanResult(NamedTuple):
    """Kết quả ``scan_cape_report``: như ``ScanResult`` kèm capability đã thăm dò."""

    findings: list[Finding]
    errors: list[ScanError]
    coverage: ProcessingState
    capability: CuckooCapability


def _error(kind: ScanErrorKind, path: str | Path, reason: str) -> ScanError:
    return ScanError(kind=kind, path=str(path), reason=reason)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _meta_str(meta: dict[str, object], key: str) -> str | None:
    """Đọc một meta dạng chuỗi; meta sai kiểu trả ``None`` thay vì crash."""
    value = meta.get(key)
    return value if isinstance(value, str) else None


def compile_ruleset(rules_path: str | Path = DEFAULT_RULES_PATH) -> RulesetOutcome:
    """Biên dịch một file ruleset thành outcome có cấu trúc (không ném ra ngoài).

    File không đọc được ⇒ ``RULESET_READ`` + ``FAILED``. Lỗi cú pháp/module ⇒
    ``COMPILE_ERROR`` + ``FAILED``. Thành công ⇒ ``rules`` khác ``None``,
    ``errors=[]``, ``coverage=COMPLETE``.
    """
    path = Path(rules_path)
    try:
        source = path.read_bytes()
    except OSError as exc:
        return RulesetOutcome(
            None,
            [_error(ScanErrorKind.RULESET_READ, path, str(exc))],
            ProcessingState.FAILED,
            None,
        )

    digest = _sha256(source)
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        return RulesetOutcome(
            None,
            [_error(ScanErrorKind.RULESET_READ, path, f"ruleset không phải UTF-8: {exc}")],
            ProcessingState.FAILED,
            digest,
        )

    try:
        rules = yara.compile(source=text)
    except yara.Error as exc:
        return RulesetOutcome(
            None,
            [_error(ScanErrorKind.COMPILE_ERROR, path, str(exc))],
            ProcessingState.FAILED,
            digest,
        )
    return RulesetOutcome(rules, [], ProcessingState.COMPLETE, digest)


def probe_cuckoo_capability() -> CuckooCapability:
    """Thăm dò module ``cuckoo`` của build YARA hiện tại.

    Biên dịch rule tối thiểu ``import "cuckoo"``. Build thiếu ``--enable-cuckoo``
    (hoặc thiếu module vì lý do khác) ⇒ ``available=False`` với cờ
    ``cuckoo_unavailable`` và ``reason`` là thông điệp compile thật; **không** có
    fallback ngầm nào được bật (spec §3.2.2).
    """
    try:
        yara.compile(source=_CUCKOO_PROBE_SOURCE)
    except yara.Error as exc:
        return CuckooCapability(
            available=False,
            flag=CUCKOO_UNAVAILABLE_FLAG,
            reason=str(exc),
            yara_version=yara.__version__,
        )
    return CuckooCapability(
        available=True, flag=None, reason="", yara_version=yara.__version__
    )


class YaraScanner:
    """Áp ruleset YARA lên bytes, chuỗi đã chuẩn hoá và report CAPEv2.

    Constructor **không** ném lỗi compile: ruleset hỏng thành ``compile_errors``
    + ``coverage=FAILED`` trên mọi kết quả quét (spec/T04: lỗi compile phải là
    processing outcome, không phải "no findings").
    """

    def __init__(
        self,
        rules_path: str | Path = DEFAULT_RULES_PATH,
        *,
        cuckoo_rules_path: str | Path = DEFAULT_CUCKOO_RULES_PATH,
        capability: CuckooCapability | None = None,
    ) -> None:
        outcome = compile_ruleset(rules_path)
        self.rules_path = Path(rules_path)
        self.rules = outcome.rules
        self.compile_errors = outcome.errors
        self.rules_sha256 = outcome.rules_sha256

        self.cuckoo_rules_path = Path(cuckoo_rules_path)
        self.cuckoo: CuckooCapability = (
            capability if capability is not None else probe_cuckoo_capability()
        )
        self.cuckoo_rules: yara.Rules | None = None
        self.cuckoo_compile_errors: list[ScanError] = []
        self.cuckoo_rules_sha256: str | None = None
        if self.cuckoo.available:
            cuckoo_outcome = compile_ruleset(self.cuckoo_rules_path)
            self.cuckoo_rules = cuckoo_outcome.rules
            self.cuckoo_compile_errors = cuckoo_outcome.errors
            self.cuckoo_rules_sha256 = cuckoo_outcome.rules_sha256

    def manifest(self) -> dict[str, object]:
        """Build/ruleset hash để log kèm kết quả (T04 nghiệm thu)."""
        return {
            "yara_version": yara.__version__,
            "rules_path": str(self.rules_path),
            "rules_sha256": self.rules_sha256,
            "cuckoo_available": self.cuckoo.available,
            "cuckoo_flag": self.cuckoo.flag,
            "cuckoo_rules_path": str(self.cuckoo_rules_path),
            "cuckoo_rules_sha256": self.cuckoo_rules_sha256,
        }

    # --- Quét bytes (file tĩnh / memory dump) ------------------------------

    def scan_bytes(
        self,
        data: bytes | bytearray | memoryview,
        *,
        detection_source: DetectionSource = DetectionSource.STATIC_STRING,
        provenance: Provenance | None = None,
    ) -> ScanResult:
        """Quét bytes thô; finding giữ offset byte và bytes khớp.

        ``data`` phải là đối tượng bytes-like. ``provenance`` là tuỳ chọn: chỉ
        truyền khi caller đã xác nhận ánh xạ dump → địa chỉ (không tự suy).
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"data phải là bytes-like, nhận {type(data).__name__}"
            )
        return self._scan_all(
            [data],
            detector_name=DetectorName.YARA_STATIC,
            detection_source=detection_source,
            provenance=[provenance],
            transform_chain=[[]],
            bytes_level=True,
        )

    # --- Quét chuỗi đã chuẩn hoá -------------------------------------------

    def scan_text(
        self,
        text: str,
        *,
        provenance: Provenance | None = None,
        transform_chain: Iterable[str] = (),
        detection_source: DetectionSource = DetectionSource.STATIC_STRING,
    ) -> ScanResult:
        """Quét một chuỗi (đã chuẩn hoá hoặc thô) — không sinh offset byte."""
        if not isinstance(text, str):
            raise TypeError(f"text phải là str, nhận {type(text).__name__}")
        return self._scan_all(
            [text],
            detector_name=DetectorName.YARA_STATIC,
            detection_source=detection_source,
            provenance=[provenance],
            transform_chain=[list(transform_chain)],
            bytes_level=False,
        )

    def scan_normalized(
        self,
        texts: NormalizedText | Iterable[NormalizedText],
        *,
        detection_source: DetectionSource = DetectionSource.STATIC_STRING,
    ) -> ScanResult:
        """Quét output Lớp 0, giữ nguyên ``provenance`` + ``transform_chain`` từng chuỗi.

        Nhận một ``NormalizedText`` hoặc một iterable của chúng. Provenance
        không bị sao chép/viết lại: chính đối tượng của ``NormalizationEngine``
        được gắn vào ``Finding``.
        """
        items = [texts] if isinstance(texts, NormalizedText) else list(texts)
        for item in items:
            if not isinstance(item.normalized_string, str):
                raise TypeError(
                    "normalized_string phải là str, nhận "
                    f"{type(item.normalized_string).__name__}"
                )
        return self._scan_all(
            [item.normalized_string for item in items],
            detector_name=DetectorName.YARA_STATIC,
            detection_source=detection_source,
            provenance=[item.provenance for item in items],
            transform_chain=[list(item.transform_chain) for item in items],
            bytes_level=False,
        )

    # --- Quét report CAPEv2 qua module Cuckoo ------------------------------

    def scan_cape_report(self, report_path: str | Path) -> CuckooScanResult:
        """Quét report CAPEv2 bằng module Cuckoo qua module-data Cuckoo.

        Report được nạp vào module qua ``modules_data={"cuckoo": <bytes>}`` —
        cùng kênh với CLI ``-x cuckoo=<report>`` (``--module-data``). Biến
        external (``externals=``) chỉ là biến điều kiện trong ``condition:``,
        không cấp dữ liệu cho module (errata SP-01).

        Module không khả dụng ⇒ ``errors=[CAPABILITY]``, ``coverage=PARTIAL``,
        ``findings=[]`` — coverage gap được ghi nhận tường minh kèm cờ cấu hình,
        không âm thầm bỏ qua và không thay bằng scanner chuỗi.
        """
        path = Path(report_path)
        if not self.cuckoo.available:
            return CuckooScanResult(
                [],
                [
                    _error(
                        ScanErrorKind.CAPABILITY,
                        path,
                        "module Cuckoo không khả dụng "
                        f"({self.cuckoo.reason}); bỏ qua quét Cuckoo, "
                        f"ghi cờ {CUCKOO_UNAVAILABLE_FLAG}",
                    )
                ],
                ProcessingState.PARTIAL,
                self.cuckoo,
            )

        if self.cuckoo_rules is None:
            return CuckooScanResult(
                [], list(self.cuckoo_compile_errors), ProcessingState.FAILED, self.cuckoo
            )

        try:
            report_bytes = path.read_bytes()
            matches = self.cuckoo_rules.match(
                filepath=str(path), modules_data={"cuckoo": report_bytes}
            )
        except (yara.Error, OSError) as exc:
            return CuckooScanResult(
                [],
                [_error(ScanErrorKind.SCAN_ERROR, path, str(exc))],
                ProcessingState.PARTIAL,
                self.cuckoo,
            )

        findings = [
            self._finding(
                match,
                detector_name=DetectorName.YARA_CUCKOO,
                detection_source=DetectionSource.SANDBOX_NETWORK_TRACE,
                provenance=None,
                transform_chain=[],
                bytes_level=False,
            )
            for match in matches
        ]
        return CuckooScanResult(findings, [], ProcessingState.COMPLETE, self.cuckoo)

    # --- Nội bộ ------------------------------------------------------------

    def _scan_all(
        self,
        payloads: list[str] | list[bytes | bytearray | memoryview],
        *,
        detector_name: DetectorName,
        detection_source: DetectionSource,
        provenance: list[Provenance | None],
        transform_chain: list[list[str]],
        bytes_level: bool,
    ) -> ScanResult:
        if self.rules is None:
            return ScanResult([], list(self.compile_errors), ProcessingState.FAILED)

        findings: list[Finding] = []
        errors: list[ScanError] = []
        for payload, item_provenance, item_chain in zip(
            payloads, provenance, transform_chain, strict=True
        ):
            # yara-python tự encode `str` sang UTF-8; chuỗi chứa lone surrogate
            # (giá trị JSON escape "\ud800" trong report CAPEv2 — đầu vào hợp lệ ở
            # pha trích xuất) làm encode mặc định ném UnicodeEncodeError và giết
            # cả lượt quét. `surrogatepass` giữ nguyên byte của mọi chuỗi hợp lệ và
            # vẫn quét được phần ASCII (regex ruleset chỉ dùng ASCII), nên không
            # tạo kẽ hở "crash để im lặng" mà spec §3.5.1 cấm.
            data = (
                payload.encode("utf-8", "surrogatepass")
                if isinstance(payload, str)
                else payload
            )
            try:
                matches = self.rules.match(data=data)
            except yara.Error as exc:
                errors.append(
                    _error(ScanErrorKind.SCAN_ERROR, self.rules_path, str(exc))
                )
                continue
            findings.extend(
                self._finding(
                    match,
                    detector_name=detector_name,
                    detection_source=detection_source,
                    provenance=item_provenance,
                    transform_chain=item_chain,
                    bytes_level=bytes_level,
                )
                for match in matches
            )

        coverage = (
            ProcessingState.PARTIAL if errors else ProcessingState.COMPLETE
        )
        return ScanResult(findings, errors, coverage)

    def _finding(
        self,
        match: yara.Match,
        *,
        detector_name: DetectorName,
        detection_source: DetectionSource,
        provenance: Provenance | None,
        transform_chain: list[str],
        bytes_level: bool,
    ) -> Finding:
        meta: dict[str, object] = dict(match.meta)
        identifiers: list[str] = []
        offsets: list[int] = []
        matched_data: list[bytes] = []
        for string_match in match.strings:
            identifiers.append(string_match.identifier)
            if not bytes_level:
                continue
            for instance in string_match.instances:
                offsets.append(instance.offset)
                matched_data.append(instance.matched_data)

        return Finding(
            detector_name=detector_name,
            rule=match.rule,
            tags=list(match.tags),
            meta=meta,
            mitre_atlas=_meta_str(meta, _MITRE_ATLAS_META),
            rule_version=_meta_str(meta, _VERSION_META),
            matched_identifiers=identifiers,
            matched_offsets=offsets,
            matched_data=matched_data,
            detection_source=detection_source,
            provenance=provenance,
            transform_chain=list(transform_chain),
        )
