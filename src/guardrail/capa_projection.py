"""CAPA Allowlist Projection — nhánh Capability (spec v1.4.0 §3.3).

Đầu vào là output `capa -j` (JSON) của Mandiant capa, chạy tĩnh trên PE
(`capa -j sample.exe`) hoặc động trên report CAPEv2 (`capa -j cape_report.json`).

Đầu ra **chỉ** gồm danh sách các định danh kỹ thuật có cấu trúc
``{tactic, technique_id, technique_name, namespace}`` (spec §3.3). Toàn bộ chuỗi
văn bản tự do trong output capa — ``description``, ``source``, ``matches`` và
captures của chúng, ``references``, ``authors``, ``examples``, siêu dữ liệu
``maec`` — bị tước bỏ hoàn toàn trước khi rời module này, nên không có đường nào
để free-text từ mẫu/telemetry đi vào context của Agent qua nhánh Capability.

Shape đã đối chiếu (nguồn chính thức `mandiant/capa`, kiểm tra 2026-09-19 trên
`master`):

- ``capa/render/json.py`` render bằng
  ``ResultDocument.model_dump_json(exclude_none=True)``.
- Tài liệu gốc: ``{"meta": Metadata, "rules": {<rule name>: RuleMatches}}``.
- ``RuleMatches``: ``{"meta": RuleMetadata, "source": str, "matches": [[address, Match], ...]}``.
- ``RuleMetadata`` gồm ``name``, ``namespace`` (None bị ``exclude_none`` lược bỏ),
  ``att&ck``, ``mbc``, ``description``, ``references``, ``examples``,
  ``capa/subscope-rule``...; ``namespace`` là định danh kỹ thuật, phần còn lại là
  free-text.
- ``att&ck`` là mảng ``AttackSpec`` — object
  ``{"parts": [...], "tactic": str, "technique": str, "subtechnique": str, "id": str}``
  — chuyển từ dạng canonical ``Tactic::Technique::Subtechnique [Identifier]``,
  ví dụ ``Execution::Command and Scripting Interpreter::Windows Command Shell [T1059.003]``.

Module chấp nhận **cả hai** dạng phần tử ``att&ck`` — object (định dạng JSON
chính thức của capa hiện hành) và chuỗi canonical — để không bám cứng vào một
phiên bản capa.

Phân biệt rõ hai kết cục "rỗng":

- *Capability rỗng hợp lệ*: tài liệu đúng shape nhưng không rule nào có mapping
  ATT&CK (rule inert) → trả ``[]``.
- *JSON sai cấu trúc*: luôn ``raise`` (``CapaaSyntaxError`` hoặc
  ``CapaStructureError``), không bao giờ trả rỗng giả.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TypedDict, cast

__all__ = [
    "ALLOWLIST_FIELDS",
    "CapabilityProjection",
    "CapaProjectionError",
    "CapaStructureError",
    "CapaaSyntaxError",
    "project_capabilities",
]


#: Bốn trường duy nhất được phép rời module này (spec §3.3).
ALLOWLIST_FIELDS: tuple[str, ...] = ("tactic", "technique_id", "technique_name", "namespace")

_SUBSCOPE_RULE_KEY = "capa/subscope-rule"
_ATTACK_KEY = "att&ck"


class CapabilityProjection(TypedDict):
    """Một capability đã chiếu qua allowlist từ một entry ATT&CK của capa."""

    tactic: str
    technique_id: str
    technique_name: str
    namespace: str


class CapaProjectionError(ValueError):
    """Lỗi cơ sở của Allowlist Projection."""


class CapaaSyntaxError(CapaProjectionError):
    """Input không parse được thành JSON."""


class CapaStructureError(CapaProjectionError):
    """JSON parse được nhưng không đúng shape tài liệu capa."""


def project_capabilities(capa_json: object) -> list[CapabilityProjection]:
    """Chiếu output ``capa -j`` về allowlist ``tactic/technique_id/technique_name/namespace``.

    ``capa_json`` nhận ``str``/``bytes``/``bytearray`` (được ``json.loads``) hoặc
    một mapping đã parse từ trước.

    Kết quả đã dedupe theo trọn bộ bốn trường, giữ thứ tự xuất hiện. Rule không
    có entry ATT&CK (inert) bị bỏ qua; rule con ``capa/subscope-rule`` bị bỏ qua
    đúng như capa không phát chúng trong output chính thức.

    Raise:
        CapaaSyntaxError: chuỗi input không phải JSON hợp lệ.
        CapaStructureError: JSON không đúng shape tài liệu capa (thiếu/`rules`
            sai kiểu, rule thiếu ``meta``, ``att&ck`` sai kiểu, entry thiếu
            định danh...).
    """
    document = _as_document(capa_json)
    rules = document.get("rules")
    if not isinstance(rules, Mapping):
        raise CapaStructureError(
            "tài liệu capa phải có khóa 'rules' là một object (rule name -> RuleMatches)"
        )

    projection: list[CapabilityProjection] = []
    seen: set[tuple[str, str, str, str]] = set()
    for rule_name, rule in rules.items():
        meta = _rule_meta(rule_name, rule)
        if meta.get(_SUBSCOPE_RULE_KEY) is True:
            continue
        namespace = _namespace(rule_name, meta)
        for entry in _attack_entries(rule_name, meta):
            tactic, technique_id, technique_name = _project_entry(rule_name, entry)
            key = (tactic, technique_id, technique_name, namespace)
            if key in seen:
                continue
            seen.add(key)
            projection.append(
                {
                    "tactic": tactic,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "namespace": namespace,
                }
            )
    return projection


def _as_document(capa_json: object) -> Mapping[str, object]:
    if isinstance(capa_json, (str, bytes, bytearray)):
        try:
            capa_json = json.loads(capa_json)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CapaaSyntaxError(f"input không phải JSON hợp lệ: {exc}") from exc
    if not isinstance(capa_json, Mapping):
        raise CapaStructureError(
            f"tài liệu capa phải là một JSON object, nhận {type(capa_json).__name__}"
        )
    return cast("Mapping[str, object]", capa_json)


def _rule_meta(rule_name: object, rule: object) -> Mapping[str, object]:
    if not isinstance(rule, Mapping):
        raise CapaStructureError(f"rule {rule_name!r} phải là một object")
    meta = rule.get("meta")
    if not isinstance(meta, Mapping):
        raise CapaStructureError(f"rule {rule_name!r} thiếu object 'meta'")
    return cast("Mapping[str, object]", meta)


def _namespace(rule_name: object, meta: Mapping[str, object]) -> str:
    namespace = meta.get("namespace", "")
    if namespace is None:
        # capa dùng None khi rule không khai báo namespace; chuẩn hoá về "".
        return ""
    if not isinstance(namespace, str):
        raise CapaStructureError(f"rule {rule_name!r}: 'namespace' phải là string hoặc null")
    return namespace


def _attack_entries(rule_name: object, meta: Mapping[str, object]) -> list[object]:
    entries = meta.get(_ATTACK_KEY, [])
    if entries is None:
        # Phòng producer ghi null thay vì [] cho rule không có mapping.
        return []
    if not isinstance(entries, list):
        raise CapaStructureError(f"rule {rule_name!r}: 'att&ck' phải là một mảng")
    return entries


def _project_entry(rule_name: object, entry: object) -> tuple[str, str, str]:
    if isinstance(entry, str):
        tactic, technique_id, technique, subtechnique = _parse_canonical_attack(rule_name, entry)
    elif isinstance(entry, Mapping):
        tactic = _entry_str(rule_name, entry, "tactic", from_parts=True)
        technique = _entry_str(rule_name, entry, "technique")
        subtechnique = _entry_str(rule_name, entry, "subtechnique")
        technique_id = _entry_str(rule_name, entry, "id")
    else:
        raise CapaStructureError(
            f"rule {rule_name!r}: entry 'att&ck' phải là object hoặc chuỗi canonical"
        )
    if not technique_id:
        raise CapaStructureError(
            f"rule {rule_name!r}: entry 'att&ck' thiếu định danh kỹ thuật 'id'"
        )
    # technique_name: theo ví dụ spec §3.5.2, dùng tên subtechnique khi có, nếu
    # không thì tên technique (phần còn lại đã được mã hoá trong technique_id).
    return tactic, technique_id, subtechnique or technique


def _entry_str(
    rule_name: object, entry: Mapping[str, object], key: str, *, from_parts: bool = False
) -> str:
    value = entry.get(key)
    if value is None and from_parts:
        parts = entry.get("parts")
        if isinstance(parts, list) and parts and isinstance(parts[0], str):
            return parts[0]
    if value is None:
        return ""
    if not isinstance(value, str):
        raise CapaStructureError(f"rule {rule_name!r}: 'att&ck[].{key}' phải là string")
    return value


def _parse_canonical_attack(
    rule_name: object, spec: str
) -> tuple[str, str, str, str]:
    """Parse dạng canonical của capa: ``Tactic::Technique::Subtechnique [Identifier]``.

    Trả ``(tactic, technique_id, technique, subtechnique)``.
    """
    parts = spec.split("::")
    tail = parts.pop() if parts else ""
    head, _, identifier = tail.rpartition(" ")
    if not (identifier.startswith("[") and identifier.endswith("]")):
        raise CapaStructureError(
            f"rule {rule_name!r}: entry 'att&ck' dạng chuỗi phải kết thúc bằng "
            f"'[<id>]': {spec!r}"
        )
    parts.append(head)
    tactic = parts[0] if len(parts) > 0 else ""
    technique = parts[1] if len(parts) > 1 else ""
    subtechnique = parts[2] if len(parts) > 2 else ""
    return tactic, identifier[1:-1], technique, subtechnique
