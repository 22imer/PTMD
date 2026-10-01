"""Đối chiếu bảng tên ATLAS của pipeline với snapshot đã ghim (SP-04).

Snapshot ATLAS-2026.09 là nguồn primary (AGENTS.md: đối chiếu mọi ``AML.T####``
trước khi khẳng định). Fixture ``atlas_snapshot_subset.json`` chứa tên nguyên
văn từ trường ``name`` của snapshot — được verify thủ công khi tạo fixture
(2026-09-20). Khi nâng snapshot, cập nhật fixture kèm nguồn + ngày fetch.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from guardrail.pipeline import ATLAS_TECHNIQUE_NAMES

FIXTURE = Path(__file__).parent / "fixtures" / "atlas_snapshot_subset.json"


def _snapshot_names() -> dict[str, str]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["techniques"]


def test_pipeline_atlas_codes_are_subset_of_snapshot() -> None:
    snapshot = _snapshot_names()
    unknown = sorted(set(ATLAS_TECHNIQUE_NAMES) - set(snapshot))
    assert unknown == [], f"mã ngoài snapshot đã ghim: {unknown}"


def test_pipeline_atlas_names_match_snapshot() -> None:
    """Tên phải khớp snapshot nguyên văn, hoặc dạng hiển thị ``<parent>: <sub>``
    cho sub-technique (mã chứa '.')."""
    snapshot = _snapshot_names()
    for code, name in ATLAS_TECHNIQUE_NAMES.items():
        expected = snapshot[code]
        if re.search(r"\.\d+$", code):
            parent_code = code.rsplit(".", 1)[0]
            allowed = {expected, f"{snapshot[parent_code]}: {expected}"}
        else:
            allowed = {expected}
        assert name in allowed, (
            f"{code}: pipeline ghi {name!r}, snapshot {expected!r} (allowed {allowed})"
        )


def test_snapshot_covers_all_codes_emittable_by_detectors() -> None:
    """Mã detectors thực sự phát sinh (T0051.001, T0054) phải có trong bảng."""
    for code in ("AML.T0051.001", "AML.T0054"):
        assert code in ATLAS_TECHNIQUE_NAMES
