"""Giao thức dataset đánh giá: manifest ghép cặp, ground truth và split (T09).

Đặc tả: spec v1.4.0 §6.1–6.2. Module chỉ **kiểm tra cấu trúc và tính nhất quán**
của manifest dựa trên dữ liệu khai báo (nhãn, hash, số liệu) — không cần, không
chạy và không unpack mẫu thật. Khi chưa có lab evidence, dataset chưa được
nghiệm thu; validator không thay bằng chứng bằng giả định.

Bất biến được kiểm (§6.1):

- Nhóm 1–4 chỉ được gán theo bảng chuẩn hoá §6.1, không suy ra từ số thứ tự.
  Pair nền lành tính → ``S_clean`` Nhóm 1 (``GT_Injection=FALSE``,
  ``GT_Malware_Behavior=BENIGN``), ``S_injected`` Nhóm 2 (``TRUE``, ``BENIGN``).
  Pair nền mã độc → ``S_clean`` Nhóm 3 (``FALSE``, ``MALICIOUS``),
  ``S_injected`` Nhóm 4 (``TRUE``, ``MALICIOUS``); ``S_clean`` của pair mã độc
  vẫn là mã độc, không đồng nghĩa lành tính.
- Quy mô: 200 pair = 100 pair nền lành tính + 100 pair nền mã độc; mỗi nhóm
  đúng 100 thành viên.
- Bất biến hành vi: ``code_region_sha256`` của clean và injected bằng nhau;
  Jaccard của behavioral signature ≥ 0.95. Pair vi phạm được **báo cáo**
  trong rejection log kèm lý do — validator không âm thầm bỏ pair khỏi manifest.

Split chống rò rỉ (§6.2): 80 pair calibration / 120 pair test; hai thành viên
của một pair luôn cùng split; không ``malware_family`` và không ``payload_family``
nào xuất hiện ở cả hai split.

``example_only: true`` dành cho manifest ví dụ về hình dạng: bỏ qua các phép
kiểm quy mô (200 pair, 100/100, 80/120, 100 mỗi nhóm) nhưng giữ nguyên toàn bộ
phép kiểm nhất quán từng pair, split và họ. Manifest ví dụ không phải dataset
được nghiệm thu.

Pair đã bị loại được ghi ở log top-level ``rejections`` (``pair_id`` + ``reason``)
và không được đồng thời nằm trong ``pairs``; ``pair_rejection_rate`` tính trên
tập ứng viên = pair đã nhận + pair bị loại. Trường không nhận diện được sẽ bị
bỏ qua (không từ chối), nhờ đó manifest có thể mở rộng mà không phá validator.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any, TypedDict

__all__ = [
    "BENIGN_ORIGIN_PAIRS",
    "CALIBRATION_PAIRS",
    "DATASET_SCHEMA_VERSION",
    "GROUP_NUMBERS",
    "GROUP_RULES",
    "GROUP_SIZE",
    "MALWARE_ORIGIN_PAIRS",
    "MIN_JACCARD",
    "TEST_PAIRS",
    "TOTAL_PAIRS",
    "DatasetCounts",
    "DatasetError",
    "DatasetValidationReport",
    "MalwareBehavior",
    "MemberRole",
    "PairOrigin",
    "PairRejection",
    "Split",
    "format_metric",
    "load_manifest",
    "validate_manifest",
    "validate_manifest_file",
]

# --- Hằng số giao thức (spec §6.1–6.2) ------------------------------------

#: Phiên bản hình dạng manifest mà validator này chấp nhận (khóa theo spec v1.4.0).
DATASET_SCHEMA_VERSION = "1.0.0"

#: Tổng số pair và phân bổ theo nguồn gốc (§6.1).
TOTAL_PAIRS = 200
BENIGN_ORIGIN_PAIRS = 100
MALWARE_ORIGIN_PAIRS = 100

#: Mỗi nhóm chuẩn hoá đúng 100 thành viên (§6.1: 4 nhóm × 100 = 400 mẫu).
GROUP_SIZE = 100
GROUP_NUMBERS = (1, 2, 3, 4)

#: Tỷ lệ split chống rò rỉ (§6.2: 40% calibration = 80 pair, 60% test = 120 pair).
CALIBRATION_PAIRS = 80
TEST_PAIRS = 120

#: Ngưỡng bất biến hành vi động (§6.1): J ≥ 0.95.
MIN_JACCARD = 0.95


class PairOrigin(StrEnum):
    """Nguồn gốc của pair: nền lành tính hoặc nền mã độc (§6.1)."""

    BENIGN = "benign"
    MALWARE = "malware"


class MemberRole(StrEnum):
    """Vai trò thành viên trong pair: ``S_clean`` hoặc ``S_injected`` (§6.1)."""

    CLEAN = "clean"
    INJECTED = "injected"


class MalwareBehavior(StrEnum):
    """Nhãn ground truth ``GT_Malware_Behavior`` (§6.1)."""

    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"


class Split(StrEnum):
    """Tập dữ liệu mà pair thuộc về (§6.2)."""

    CALIBRATION = "calibration"
    TEST = "test"


#: Bảng nhóm chuẩn hoá §6.1: (origin, vai trò) → (nhóm, GT_Injection, GT_Malware_Behavior).
GROUP_RULES: dict[tuple[PairOrigin, MemberRole], tuple[int, bool, MalwareBehavior]] = {
    (PairOrigin.BENIGN, MemberRole.CLEAN): (1, False, MalwareBehavior.BENIGN),
    (PairOrigin.BENIGN, MemberRole.INJECTED): (2, True, MalwareBehavior.BENIGN),
    (PairOrigin.MALWARE, MemberRole.CLEAN): (3, False, MalwareBehavior.MALICIOUS),
    (PairOrigin.MALWARE, MemberRole.INJECTED): (4, True, MalwareBehavior.MALICIOUS),
}

_ORIGINS = (PairOrigin.BENIGN.value, PairOrigin.MALWARE.value)
_SPLITS = (Split.CALIBRATION.value, Split.TEST.value)


# --- Kiểu report -----------------------------------------------------------


class DatasetError(TypedDict):
    """Một lỗi của manifest: ``path`` là JSON Pointer, ``reason`` là mô tả."""

    path: str
    reason: str


class PairRejection(TypedDict):
    """Một pair bị loại khỏi dataset kèm lý do (§6.1 ``pair_rejection_rate``)."""

    pair_id: str
    path: str
    reason: str


class DatasetCounts(TypedDict):
    """Thống kê kiểm đếm theo khai báo trong manifest."""

    pairs: int
    groups: dict[int, int]
    splits: dict[str, int]


class DatasetValidationReport(TypedDict):
    """Kết quả ``validate_manifest`` (JSON-serializable)."""

    ok: bool
    example_only: bool
    errors: list[DatasetError]
    counts: DatasetCounts
    rejections: list[PairRejection]
    pair_rejection_rate: str


# --- Helper ----------------------------------------------------------------


def format_metric(numerator: int, denominator: int, *, digits: int = 4) -> str:
    """Định dạng metric dạng phân số; mẫu số bằng 0 → ``"N/A"`` (§6.6: không báo 100%)."""
    if denominator == 0:
        return "N/A"
    return f"{numerator / denominator:.{digits}f}"


def load_manifest(path: str | Path) -> object:
    """Đọc manifest JSON từ đĩa; lỗi cú pháp/IO để nguyên cho caller xử lý."""
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_manifest_file(path: str | Path) -> DatasetValidationReport:
    """Đọc manifest từ đĩa rồi kiểm bằng ``validate_manifest``."""
    return validate_manifest(load_manifest(path))


def _error(path: str, reason: str) -> DatasetError:
    return DatasetError(path=path, reason=reason)


def _type_name(value: object) -> str:
    return type(value).__name__


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _build_report(
    *,
    errors: list[DatasetError],
    groups: dict[int, int],
    splits: dict[str, int],
    pair_count: int,
    rejections: list[PairRejection],
    accepted_ids: set[str],
    example_only: bool,
) -> DatasetValidationReport:
    rejected_ids = {entry["pair_id"] for entry in rejections}
    candidates = accepted_ids | rejected_ids
    return DatasetValidationReport(
        ok=not errors,
        example_only=example_only,
        errors=errors,
        counts=DatasetCounts(
            pairs=pair_count,
            groups=dict(groups),
            splits=dict(splits),
        ),
        rejections=rejections,
        pair_rejection_rate=format_metric(len(rejected_ids), len(candidates)),
    )


def _check_family(
    first_use: dict[tuple[str, str], tuple[str, str]],
    field: str,
    family: str,
    split: str | None,
    path: str,
    errors: list[DatasetError],
) -> None:
    """Chặn một họ dùng ở cả hai split (§6.2), báo tại vị trí vi phạm."""
    if split is None:
        return
    key = (field, family)
    seen = first_use.get(key)
    if seen is None:
        first_use[key] = (split, f"{path}/{field}")
        return
    seen_split, seen_path = seen
    if seen_split != split:
        errors.append(
            _error(
                f"{path}/{field}",
                f"{field} {family!r} đã dùng ở split '{seen_split}' ({seen_path}) — "
                f"cấm xuất hiện ở cả hai split (§6.2)",
            )
        )


def _check_member(
    member: object,
    path: str,
    *,
    role: MemberRole,
    origin: PairOrigin | None,
    errors: list[DatasetError],
) -> tuple[int | None, str | None]:
    """Kiểm một thành viên pair; trả ``(nhóm, split)`` đã khai để caller kiểm đếm."""
    if not isinstance(member, Mapping):
        errors.append(
            _error(path, f"thành viên pair phải là object, nhận {_type_name(member)}")
        )
        return None, None

    if not _is_text(member.get("sample_id")):
        errors.append(_error(f"{path}/sample_id", "thiếu 'sample_id' hoặc sai kiểu"))
    for field in ("sha256", "code_region_sha256"):
        if not _is_text(member.get(field)):
            errors.append(_error(f"{path}/{field}", f"thiếu '{field}' hoặc sai kiểu"))

    group = member.get("group")
    if not isinstance(group, int) or isinstance(group, bool) or group not in GROUP_NUMBERS:
        errors.append(
            _error(
                f"{path}/group",
                f"'group' phải là số nguyên 1–4, nhận {group!r}",
            )
        )
        group = None

    injection = member.get("GT_Injection")
    if not isinstance(injection, bool):
        errors.append(
            _error(f"{path}/GT_Injection", f"'GT_Injection' phải là boolean, nhận {injection!r}")
        )
        injection = None

    behavior = member.get("GT_Malware_Behavior")
    if behavior not in (MalwareBehavior.MALICIOUS.value, MalwareBehavior.BENIGN.value):
        errors.append(
            _error(
                f"{path}/GT_Malware_Behavior",
                f"'GT_Malware_Behavior' phải là 'MALICIOUS' hoặc 'BENIGN', nhận {behavior!r}",
            )
        )
        behavior = None

    member_split = member.get("split")
    if member_split not in _SPLITS:
        errors.append(
            _error(f"{path}/split", f"'split' phải là 'calibration' hoặc 'test', nhận {member_split!r}")
        )
        member_split = None

    if origin is not None:
        expected_group, expected_injection, expected_behavior = GROUP_RULES[(origin, role)]
        context = f"origin '{origin.value}', thành viên '{role.value}'"
        if group is not None and group != expected_group:
            errors.append(
                _error(
                    f"{path}/group",
                    f"Nhóm {group} sai với bảng nhóm §6.1: {context} phải thuộc Nhóm {expected_group}",
                )
            )
        if injection is not None and injection != expected_injection:
            errors.append(
                _error(
                    f"{path}/GT_Injection",
                    f"GT_Injection phải là {expected_injection} cho Nhóm {expected_group} "
                    f"({context}), nhận {injection}",
                )
            )
        if behavior is not None and behavior != expected_behavior.value:
            errors.append(
                _error(
                    f"{path}/GT_Malware_Behavior",
                    f"GT_Malware_Behavior phải là '{expected_behavior.value}' cho Nhóm "
                    f"{expected_group} ({context}), nhận '{behavior}'",
                )
            )

    return group, member_split


def _check_invariance(
    pair: Mapping[str, Any],
    path: str,
    log_id: str,
    errors: list[DatasetError],
    rejections: list[PairRejection],
) -> None:
    """Kiểm bất biến hành vi động (§6.1); vi phạm → lỗi kèm rejection có lý do."""
    invariance = pair.get("invariance")
    if not isinstance(invariance, Mapping):
        errors.append(
            _error(
                f"{path}/invariance",
                f"thiếu object 'invariance' bắt buộc, nhận {_type_name(invariance)}",
            )
        )
        return

    jaccard = invariance.get("jaccard")
    jaccard_path = f"{path}/invariance/jaccard"
    if not _is_number(jaccard):
        errors.append(_error(jaccard_path, f"'jaccard' phải là số, nhận {jaccard!r}"))
    elif not 0.0 <= jaccard <= 1.0:
        errors.append(_error(jaccard_path, f"'jaccard' phải nằm trong [0, 1], nhận {jaccard}"))
    elif jaccard < MIN_JACCARD:
        reason = f"Jaccard {jaccard} < {MIN_JACCARD} (bất biến hành vi §6.1)"
        errors.append(_error(jaccard_path, reason))
        rejections.append(PairRejection(pair_id=log_id, path=jaccard_path, reason=reason))


def _check_declared_rejections(
    manifest: Mapping[str, Any],
    accepted_ids: set[str],
    errors: list[DatasetError],
    rejections: list[PairRejection],
) -> None:
    """Kiểm log ``rejections``: mỗi entry cần ``pair_id`` + ``reason``; pair bị loại không được nằm trong ``pairs``."""
    declared: object = manifest.get("rejections", [])
    if declared is None:
        declared = []
    if not isinstance(declared, list):
        errors.append(
            _error("/rejections", f"'rejections' phải là mảng, nhận {_type_name(declared)}")
        )
        return

    seen_ids: set[str] = set()
    for index, entry in enumerate(declared):
        entry_path = f"/rejections/{index}"
        if not isinstance(entry, Mapping):
            errors.append(
                _error(entry_path, f"phần tử rejection phải là object, nhận {_type_name(entry)}")
            )
            continue

        rejected_id = entry.get("pair_id")
        reason = entry.get("reason")
        if not _is_text(rejected_id):
            errors.append(_error(f"{entry_path}/pair_id", "thiếu 'pair_id' hoặc sai kiểu"))
            rejected_id = None
        if not _is_text(reason):
            errors.append(_error(f"{entry_path}/reason", "thiếu 'reason' hoặc sai kiểu"))
            reason = ""

        if rejected_id is not None:
            if rejected_id in seen_ids:
                errors.append(
                    _error(f"{entry_path}/pair_id", f"'pair_id' {rejected_id!r} bị trùng trong rejection log")
                )
            if rejected_id in accepted_ids:
                errors.append(
                    _error(
                        f"{entry_path}/pair_id",
                        f"pair {rejected_id!r} vừa nằm trong 'pairs' vừa nằm trong rejection log",
                    )
                )
            seen_ids.add(rejected_id)

        rejections.append(
            PairRejection(
                pair_id=rejected_id if rejected_id is not None else f"rejections[{index}]",
                path=entry_path,
                reason=reason,
            )
        )


# --- API chính -------------------------------------------------------------


def validate_manifest(manifest: object) -> DatasetValidationReport:
    """Kiểm manifest ghép cặp; trả report có cấu trúc thay vì raise.

    Dữ liệu đầu vào là untrusted: mọi sai lệch cấu trúc/nhất quán (§6.1–6.2) trở
    thành một ``{path, reason}`` trong ``errors``; ``ok`` chỉ ``True`` khi
    ``errors`` rỗng. ``counts`` đếm theo khai báo trong manifest (census) để phản
    ánh trung thực dữ liệu nhận vào ngay cả khi manifest sai.
    """
    errors: list[DatasetError] = []
    rejections: list[PairRejection] = []
    groups: dict[int, int] = dict.fromkeys(GROUP_NUMBERS, 0)
    splits: dict[str, int] = dict.fromkeys(_SPLITS, 0)
    origins: dict[str, int] = dict.fromkeys(_ORIGINS, 0)
    accepted_ids: set[str] = set()

    if not isinstance(manifest, Mapping):
        errors.append(_error("/", f"manifest phải là object, nhận {_type_name(manifest)}"))
        return _build_report(
            errors=errors,
            groups=groups,
            splits=splits,
            pair_count=0,
            rejections=rejections,
            accepted_ids=accepted_ids,
            example_only=False,
        )

    example_only = manifest.get("example_only") is True

    schema_version = manifest.get("schema_version")
    if not _is_text(schema_version):
        errors.append(_error("/schema_version", "thiếu 'schema_version' hoặc sai kiểu"))
    elif schema_version != DATASET_SCHEMA_VERSION:
        errors.append(
            _error(
                "/schema_version",
                f"'schema_version' phải là '{DATASET_SCHEMA_VERSION}', nhận {schema_version!r}",
            )
        )

    pairs = manifest.get("pairs")
    if not isinstance(pairs, list):
        errors.append(
            _error("/pairs", f"thiếu mảng 'pairs' bắt buộc, nhận {_type_name(pairs)}")
        )
        return _build_report(
            errors=errors,
            groups=groups,
            splits=splits,
            pair_count=0,
            rejections=rejections,
            accepted_ids=accepted_ids,
            example_only=example_only,
        )

    first_family_use: dict[tuple[str, str], tuple[str, str]] = {}

    for index, pair in enumerate(pairs):
        path = f"/pairs/{index}"
        if not isinstance(pair, Mapping):
            errors.append(
                _error(path, f"pair phải là object, nhận {_type_name(pair)}")
            )
            continue

        pair_id = pair.get("pair_id")
        if not _is_text(pair_id):
            errors.append(_error(f"{path}/pair_id", "thiếu 'pair_id' hoặc sai kiểu"))
            log_id = f"pairs[{index}]"
        else:
            log_id = pair_id
            if pair_id in accepted_ids:
                errors.append(
                    _error(f"{path}/pair_id", f"'pair_id' {pair_id!r} bị trùng trong 'pairs'")
                )
            accepted_ids.add(pair_id)

        origin_raw = pair.get("origin")
        origin: PairOrigin | None = None
        if origin_raw not in _ORIGINS:
            errors.append(
                _error(f"{path}/origin", f"'origin' phải là 'benign' hoặc 'malware', nhận {origin_raw!r}")
            )
        else:
            origin = PairOrigin(origin_raw)
            origins[origin_raw] += 1

        split_raw = pair.get("split")
        pair_split: str | None = None
        if split_raw not in _SPLITS:
            errors.append(
                _error(f"{path}/split", f"'split' phải là 'calibration' hoặc 'test', nhận {split_raw!r}")
            )
        else:
            pair_split = split_raw
            splits[pair_split] += 1

        family = pair.get("malware_family")
        if _is_text(family):
            _check_family(first_family_use, "malware_family", family, pair_split, path, errors)
        elif family is None and origin is PairOrigin.BENIGN:
            pass
        elif family is None and origin is PairOrigin.MALWARE:
            errors.append(
                _error(
                    f"{path}/malware_family",
                    "pair nền mã độc phải khai 'malware_family' không rỗng (§6.2)",
                )
            )
        else:
            errors.append(
                _error(
                    f"{path}/malware_family",
                    f"'malware_family' phải là chuỗi không rỗng hoặc null, nhận {family!r}",
                )
            )

        payload_family = pair.get("payload_family")
        if _is_text(payload_family):
            _check_family(first_family_use, "payload_family", payload_family, pair_split, path, errors)
        else:
            errors.append(
                _error(f"{path}/payload_family", f"thiếu 'payload_family' hoặc sai kiểu, nhận {payload_family!r}")
            )

        if "source" in pair and not _is_text(pair.get("source")):
            errors.append(_error(f"{path}/source", f"'source' sai kiểu, nhận {pair.get('source')!r}"))

        clean_group, clean_split = _check_member(
            pair.get("clean"), f"{path}/clean", role=MemberRole.CLEAN, origin=origin, errors=errors
        )
        injected_group, injected_split = _check_member(
            pair.get("injected"), f"{path}/injected", role=MemberRole.INJECTED, origin=origin, errors=errors
        )
        for group in (clean_group, injected_group):
            if group is not None:
                groups[group] += 1

        if clean_split is not None and injected_split is not None:
            if clean_split != injected_split:
                errors.append(
                    _error(
                        f"{path}/injected/split",
                        "hai thành viên của một pair phải cùng split (§6.2): "
                        f"clean '{clean_split}', injected '{injected_split}'",
                    )
                )
            elif pair_split is not None and pair_split != injected_split:
                errors.append(
                    _error(
                        f"{path}/injected/split",
                        "'split' của thành viên phải khớp 'split' của pair: "
                        f"pair '{pair_split}', thành viên '{injected_split}'",
                    )
                )

        clean = pair.get("clean")
        injected = pair.get("injected")
        clean_hash = clean.get("code_region_sha256") if isinstance(clean, Mapping) else None
        injected_hash = injected.get("code_region_sha256") if isinstance(injected, Mapping) else None
        if _is_text(clean_hash) and _is_text(injected_hash) and clean_hash != injected_hash:
            reason = (
                "code_region_sha256 của clean và injected phải bằng nhau "
                f"(bất biến vùng code §6.1): {clean_hash} != {injected_hash}"
            )
            hash_path = f"{path}/injected/code_region_sha256"
            errors.append(_error(hash_path, reason))
            rejections.append(PairRejection(pair_id=log_id, path=hash_path, reason=reason))

        _check_invariance(pair, path, log_id, errors, rejections)

    if not example_only:
        if len(pairs) != TOTAL_PAIRS:
            errors.append(
                _error("/pairs", f"manifest phải có {TOTAL_PAIRS} pair, nhận {len(pairs)}")
            )
        if origins[PairOrigin.BENIGN.value] != BENIGN_ORIGIN_PAIRS:
            errors.append(
                _error(
                    "/pairs",
                    f"phải có {BENIGN_ORIGIN_PAIRS} pair nền lành tính, nhận "
                    f"{origins[PairOrigin.BENIGN.value]}",
                )
            )
        if origins[PairOrigin.MALWARE.value] != MALWARE_ORIGIN_PAIRS:
            errors.append(
                _error(
                    "/pairs",
                    f"phải có {MALWARE_ORIGIN_PAIRS} pair nền mã độc, nhận "
                    f"{origins[PairOrigin.MALWARE.value]}",
                )
            )
        for group in GROUP_NUMBERS:
            if groups[group] != GROUP_SIZE:
                errors.append(
                    _error(
                        "/pairs",
                        f"Nhóm {group} phải có {GROUP_SIZE} thành viên, nhận {groups[group]}",
                    )
                )
        if splits[Split.CALIBRATION.value] != CALIBRATION_PAIRS:
            errors.append(
                _error(
                    "/pairs",
                    f"split 'calibration' phải có {CALIBRATION_PAIRS} pair, nhận "
                    f"{splits[Split.CALIBRATION.value]}",
                )
            )
        if splits[Split.TEST.value] != TEST_PAIRS:
            errors.append(
                _error(
                    "/pairs",
                    f"split 'test' phải có {TEST_PAIRS} pair, nhận {splits[Split.TEST.value]}",
                )
            )

    _check_declared_rejections(manifest, accepted_ids, errors, rejections)

    return _build_report(
        errors=errors,
        groups=groups,
        splits=splits,
        pair_count=len(pairs),
        rejections=rejections,
        accepted_ids=accepted_ids,
        example_only=example_only,
    )
