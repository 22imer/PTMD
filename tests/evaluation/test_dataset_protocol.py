"""Chốt giao thức dataset T09: manifest ghép cặp, ground truth và split (§6.1–6.2).

Manifest dùng ở đây là dữ liệu tổng hợp hoàn toàn (không có mẫu thật, không chạy
mẫu): ``make_manifest`` dựng một manifest nhất quán theo §6.1–6.2, rồi mỗi test
đột biến đúng một luật để chứng minh validator bắt được lỗi kèm lý do. Fixture
`tests/fixtures/dataset_manifest_example.json` là ví dụ hình dạng 6 pair, tự khai
``example_only`` nên chỉ đi qua các phép kiểm từng pair.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from guardrail.evaluation.dataset_protocol import (
    CALIBRATION_PAIRS,
    GROUP_SIZE,
    MIN_JACCARD,
    TEST_PAIRS,
    TOTAL_PAIRS,
    format_metric,
    validate_manifest,
    validate_manifest_file,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "dataset_manifest_example.json"

#: Họ mã độc chia theo split — không họ nào xuất hiện ở cả hai tập (§6.2).
MALWARE_FAMILIES = {
    "calibration": ["RedLine", "SmokeLoader"],
    "test": ["LockBit", "QakBot"],
}

#: Họ payload (§6.2) chia theo split, dùng bốn họ nêu trong spec.
PAYLOAD_FAMILIES = {
    "calibration": ["Direct override", "False benign claim"],
    "test": ["Role impersonation", "Multi-encoding"],
}


def _sha256(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def make_manifest(
    pairs: int = TOTAL_PAIRS,
    *,
    example_only: bool = False,
    source: str = "synthetic://t09-generator",
) -> dict:
    """Sinh manifest tổng hợp nhất quán theo §6.1–6.2.

    Quy ước sinh: pair chẵn là nền lành tính, pair lẻ là nền mã độc (200 pair →
    100/100); cứ 5 pair liên tiếp thì 2 pair thuộc calibration (80/120); họ mã độc
    và họ payload lấy từ pool riêng của từng split; ``jaccard`` chạy 0.95–0.99 để
    chạm đúng ngưỡng; ``code_region_sha256`` dùng chung giữa hai thành viên.
    """
    manifest_pairs: list[dict] = []
    position_in_split = {"calibration": 0, "test": 0}

    for index in range(pairs):
        split = "calibration" if index % 5 < 2 else "test"
        position = position_in_split[split]
        position_in_split[split] += 1

        origin = "benign" if index % 2 == 0 else "malware"
        pair_id = f"PAIR-{index:03d}"
        behavior = "BENIGN" if origin == "benign" else "MALICIOUS"
        clean_group, injected_group = (1, 2) if origin == "benign" else (3, 4)
        malware_family = None
        if origin == "malware":
            pool = MALWARE_FAMILIES[split]
            malware_family = pool[position % len(pool)]

        manifest_pairs.append(
            {
                "pair_id": pair_id,
                "origin": origin,
                "malware_family": malware_family,
                "payload_family": PAYLOAD_FAMILIES[split][position % len(PAYLOAD_FAMILIES[split])],
                "split": split,
                "source": source,
                "clean": {
                    "sample_id": f"{pair_id}-CLEAN",
                    "sha256": _sha256(pair_id, "clean"),
                    "code_region_sha256": _sha256(pair_id, "code-region"),
                    "group": clean_group,
                    "GT_Injection": False,
                    "GT_Malware_Behavior": behavior,
                    "split": split,
                },
                "injected": {
                    "sample_id": f"{pair_id}-INJECTED",
                    "sha256": _sha256(pair_id, "injected"),
                    "code_region_sha256": _sha256(pair_id, "code-region"),
                    "group": injected_group,
                    "GT_Injection": True,
                    "GT_Malware_Behavior": behavior,
                    "split": split,
                },
                "invariance": {"jaccard": round(0.95 + 0.01 * (index % 5), 2)},
            }
        )

    return {
        "schema_version": "1.0.0",
        "example_only": example_only,
        "pairs": manifest_pairs,
        "rejections": [],
    }


@pytest.fixture
def manifest() -> dict:
    return make_manifest()


def _reasons(report: dict) -> str:
    return " | ".join(f"{error['path']}: {error['reason']}" for error in report["errors"])


def _pick(manifest: dict, *, origin: str, split: str) -> dict:
    """Pair đầu tiên khớp origin/split, dùng để dựng đột biến có chủ đích."""
    for pair in manifest["pairs"]:
        if pair["origin"] == origin and pair["split"] == split:
            return pair
    raise AssertionError(f"manifest không có pair origin={origin} split={split}")


def test_manifest_tong_hop_hop_le(manifest):
    report = validate_manifest(manifest)

    assert report["errors"] == [], _reasons(report)
    assert report["ok"] is True
    assert report["example_only"] is False
    assert report["counts"] == {
        "pairs": TOTAL_PAIRS,
        "groups": {1: GROUP_SIZE, 2: GROUP_SIZE, 3: GROUP_SIZE, 4: GROUP_SIZE},
        "splits": {"calibration": CALIBRATION_PAIRS, "test": TEST_PAIRS},
    }
    assert report["rejections"] == []
    assert report["pair_rejection_rate"] == "0.0000"


def test_thieu_pair_bi_tu_choi():
    report = validate_manifest(make_manifest(pairs=TOTAL_PAIRS - 1))

    assert report["ok"] is False
    assert report["counts"]["pairs"] == TOTAL_PAIRS - 1
    assert any(
        error["path"] == "/pairs" and str(TOTAL_PAIRS) in error["reason"]
        for error in report["errors"]
    ), _reasons(report)


def test_nhom_thieu_thanh_vien_bi_tu_choi(manifest):
    """Lật hẳn một pair lành tính sang nền mã độc → lệch cỡ nhóm và tỷ lệ nguồn gốc."""
    pair = _pick(manifest, origin="benign", split="calibration")
    pair["origin"] = "malware"
    pair["malware_family"] = MALWARE_FAMILIES["calibration"][0]
    pair["clean"]["group"] = 3
    pair["injected"]["group"] = 4
    pair["clean"]["GT_Malware_Behavior"] = "MALICIOUS"
    pair["injected"]["GT_Malware_Behavior"] = "MALICIOUS"

    report = validate_manifest(manifest)

    assert report["ok"] is False
    assert report["counts"]["groups"] == {1: 99, 2: 99, 3: 101, 4: 101}
    assert any(
        "Nhóm 1" in error["reason"] and str(GROUP_SIZE) in error["reason"]
        for error in report["errors"]
    ), _reasons(report)


def test_malware_family_xuyen_split_bi_tu_choi(manifest):
    leaked = _pick(manifest, origin="malware", split="calibration")["malware_family"]
    pair = _pick(manifest, origin="malware", split="test")
    pair["malware_family"] = leaked

    report = validate_manifest(manifest)

    assert report["ok"] is False
    assert any(
        error["path"].endswith("/malware_family")
        and leaked in error["reason"]
        and "cả hai split" in error["reason"]
        for error in report["errors"]
    ), _reasons(report)


def test_payload_family_xuyen_split_bi_tu_choi(manifest):
    leaked = _pick(manifest, origin="benign", split="calibration")["payload_family"]
    pair = _pick(manifest, origin="benign", split="test")
    pair["payload_family"] = leaked

    report = validate_manifest(manifest)

    assert report["ok"] is False
    assert any(
        error["path"].endswith("/payload_family")
        and leaked in error["reason"]
        and "cả hai split" in error["reason"]
        for error in report["errors"]
    ), _reasons(report)


def test_hai_thanh_vien_khac_split_bi_tu_choi(manifest):
    pair = manifest["pairs"][0]
    pair["injected"]["split"] = "test" if pair["split"] == "calibration" else "calibration"

    report = validate_manifest(manifest)

    assert report["ok"] is False
    assert any("cùng split" in error["reason"] for error in report["errors"]), _reasons(report)


def test_jaccard_duoi_nguong_bi_loai_kem_ly_do(manifest):
    pair = manifest["pairs"][2]
    pair["invariance"]["jaccard"] = 0.94

    report = validate_manifest(manifest)

    assert report["ok"] is False
    assert any("0.94" in error["reason"] for error in report["errors"]), _reasons(report)
    rejection = next(
        entry for entry in report["rejections"] if entry["pair_id"] == pair["pair_id"]
    )
    assert "Jaccard 0.94" in rejection["reason"]
    assert rejection["path"].endswith("/invariance/jaccard")
    assert report["pair_rejection_rate"] == format_metric(1, TOTAL_PAIRS + 1)


def test_jaccard_dung_nguong_duoc_chap_nhan(manifest):
    for pair in manifest["pairs"]:
        pair["invariance"]["jaccard"] = MIN_JACCARD

    report = validate_manifest(manifest)

    assert report["ok"] is True, _reasons(report)


@pytest.mark.parametrize(
    ("origin", "role", "field", "bad_value", "expected_group"),
    [
        ("benign", "clean", "group", 3, 3),
        ("benign", "clean", "GT_Injection", True, 1),
        ("benign", "injected", "GT_Malware_Behavior", "MALICIOUS", 2),
        ("malware", "clean", "GT_Malware_Behavior", "BENIGN", 3),
    ],
)
def test_gt_sai_theo_nhom_bi_tu_choi(manifest, origin, role, field, bad_value, expected_group):
    """Nhóm 1–4 bám bảng §6.1: S_clean của pair mã độc vẫn là MALICIOUS, không mặc định BENIGN."""
    pair = _pick(manifest, origin=origin, split="calibration")
    pair[role][field] = bad_value
    index = manifest["pairs"].index(pair)

    report = validate_manifest(manifest)

    assert report["ok"] is False
    expected_path = f"/pairs/{index}/{role}/{field}"
    assert any(
        error["path"] == expected_path and f"Nhóm {expected_group}" in error["reason"]
        for error in report["errors"]
    ), _reasons(report)


def test_thieu_truong_bat_buoc_bi_tu_choi(manifest):
    pair = manifest["pairs"][0]
    del pair["payload_family"]
    del pair["injected"]["code_region_sha256"]

    report = validate_manifest(manifest)

    assert report["ok"] is False
    paths = {error["path"] for error in report["errors"]}
    assert "/pairs/0/payload_family" in paths
    assert "/pairs/0/injected/code_region_sha256" in paths


def test_pair_ma_doc_thieu_family_bi_tu_choi(manifest):
    pair = _pick(manifest, origin="malware", split="test")
    pair["malware_family"] = None

    report = validate_manifest(manifest)

    assert report["ok"] is False
    assert any(error["path"].endswith("/malware_family") for error in report["errors"]), _reasons(
        report
    )


def test_code_region_hash_lech_bi_loai_kem_ly_do(manifest):
    pair = manifest["pairs"][3]
    pair["injected"]["code_region_sha256"] = _sha256("other", "code-region")

    report = validate_manifest(manifest)

    assert report["ok"] is False
    rejection = next(
        entry for entry in report["rejections"] if entry["pair_id"] == pair["pair_id"]
    )
    assert "code_region_sha256" in rejection["reason"]
    assert "bất biến" in rejection["reason"]


def test_rejection_log_duoc_tinh_ty_le(manifest):
    manifest["rejections"] = [{"pair_id": "PAIR-999", "reason": "Jaccard 0.91 < 0.95 (§6.1)"}]

    report = validate_manifest(manifest)

    assert report["ok"] is True, _reasons(report)
    assert report["pair_rejection_rate"] == format_metric(1, TOTAL_PAIRS + 1)
    assert report["counts"]["pairs"] == TOTAL_PAIRS


def test_pair_vua_nhan_vua_bi_loai_bi_tu_choi(manifest):
    manifest["rejections"] = [{"pair_id": manifest["pairs"][0]["pair_id"], "reason": "lý do bất kỳ"}]

    report = validate_manifest(manifest)

    assert report["ok"] is False
    assert any("rejection log" in error["reason"] for error in report["errors"]), _reasons(report)


def test_manifest_vi_du_trong_fixture_hop_le():
    report = validate_manifest_file(EXAMPLE_FIXTURE_PATH)

    assert report["errors"] == [], _reasons(report)
    assert report["ok"] is True
    assert report["example_only"] is True
    assert report["counts"]["pairs"] == 6


def test_example_only_moi_bo_qua_kiem_quy_mo():
    """Cùng fixture đó, khi tắt cờ ví dụ → bị từ chối vì không đủ 200 pair."""
    example = json.loads(EXAMPLE_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert example["example_only"] is True

    report = validate_manifest({**example, "example_only": False})

    assert report["ok"] is False
    assert any(str(TOTAL_PAIRS) in error["reason"] for error in report["errors"]), _reasons(report)


def test_manifest_sai_cau_truc_bi_tu_choi():
    report = validate_manifest({"schema_version": "9.9.9", "pairs": {"PAIR-000": {}}})

    assert report["ok"] is False
    assert {error["path"] for error in report["errors"]} == {"/schema_version", "/pairs"}
    assert report["counts"]["pairs"] == 0


def test_format_metric_mau_so_bang_khong_tra_na():
    assert format_metric(0, 0) == "N/A"
    assert format_metric(1, 4) == "0.2500"
