"""CAPA Allowlist Projection — nhánh Capability (spec v1.4.0 §3.3).

Đầu vào là output `capa -j` (JSON) của Mandiant capa, chạy tĩnh trên PE
(`capa -j sample.exe`) hoặc động trên report CAPEv2 (`capa -j cape_report.json`).

Đầu ra **chỉ** gồm danh sách các định danh kỹ thuật có cấu trúc
``{tactic, technique_id, technique_name, namespace}`` (spec §3.3). Toàn bộ chuỗi
văn bản tự do trong output capa — ``description``, ``source``, ``matches`` và
captures của chúng, ``references``, ``authors``, ``examples``, siêu dữ liệu
``maec`` — bị tước bỏ hoàn toàn trước khi rời module này, nên không có đường nào
để free-text từ mẫu/telemetry đi vào context của Agent qua nhánh Capability.

Shape đã đối chiếu (nguồn chính thức `mandiant/capa`, đối chiếu 2026-09-19 trên
`master` **và** trên bản phát hành `capa==9.1.0`):

- ``capa/render/json.py`` render bằng
  ``ResultDocument.from_capa(...).model_dump_json(exclude_none=True)`` — **không**
  truyền ``by_alias``.
- Vì pydantic serialize theo *tên field* chứ không theo *alias*, JSON thật phát
  ra khóa **``attack``** (field ``attack`` có alias ``att&ck``) và cờ rule con là
  **``is_subscope_rule``** (field ``is_subscope_rule`` có alias ``capa/subscope``).
  Các khóa alias ``att&ck`` / ``capa/subscope`` **không** xuất hiện trong output
  `capa -j`; ``capa/subscope-rule`` chỉ là khóa meta trong YAML rule nguồn và
  cũng không xuất hiện trong JSON (rule con bị ``ResultDocument.from_capa`` lọc
  bỏ trước khi serialize).
- Tài liệu gốc: ``{"meta": Metadata, "rules": {<rule name>: RuleMatches}}``.
- ``RuleMatches``: ``{"meta": RuleMetadata, "source": str, "matches": [[address, Match], ...]}``.
- ``RuleMetadata`` gồm ``name``, ``namespace`` (None bị ``exclude_none`` lược bỏ),
  ``attack``, ``mbc``, ``description``, ``references``, ``examples``,
  ``is_subscope_rule``, ``maec``...; ``namespace`` là định danh kỹ thuật, phần
  còn lại là free-text.
- ``attack`` là mảng ``AttackSpec`` — object
  ``{"parts": [...], "tactic": str, "technique": str, "subtechnique": str, "id": str}``
  — chuyển từ dạng canonical ``Tactic::Technique::Subtechnique [Identifier]``,
  ví dụ ``Execution::Command and Scripting Interpreter::Windows Command Shell [T1059.003]``.

Đọc ``attack`` trước, chỉ fallback sang ``att&ck`` khi tài liệu **không** có khóa
``attack`` (dung sai cho tài liệu cũ/hand-made in theo alias). Một giá trị
``attack`` hiện diện nhưng sai kiểu luôn ``raise``, không bao giờ bị bỏ qua im
lặng.

Module chấp nhận **cả hai** dạng phần tử ``attack`` — object (định dạng JSON
chính thức của capa) và chuỗi canonical. Dạng chuỗi canonical
(``Tactic::Technique::Subtechnique [Identifier]``) là từ vựng của **YAML rule
nguồn**, không phải dạng nào mà bất kỳ phiên bản capa nào phát ra trong JSON; nó
được giữ như dung sai robustness, không phải để tương thích producer.

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

#: Khóa ATT&CK trong output JSON thật (field ``attack``, alias ``att&ck``).
_ATTACK_KEY = "attack"
#: Khóa alias cũ — chỉ có ở tài liệu in theo alias, không phải output `capa -j`.
_ATTACK_KEY_LEGACY = "att&ck"
#: Các khóa đánh dấu rule con (subscope), theo thứ tự: tên field thật, alias
#: pydantic của field đó, và khóa meta YAML nguồn (không xuất hiện trong JSON).
_SUBSCOPE_RULE_KEYS = ("is_subscope_rule", "capa/subscope", "capa/subscope-rule")


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
    có entry ATT&CK (inert) bị bỏ qua; rule con (``is_subscope_rule``) bị bỏ qua
    đúng như capa không phát chúng trong output chính thức.

    Raise:
        CapaaSyntaxError: chuỗi input không phải JSON hợp lệ.
        CapaStructureError: JSON không đúng shape tài liệu capa (thiếu/`rules`
            sai kiểu, rule thiếu ``meta``, ``attack`` sai kiểu, entry thiếu
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
        if any(meta.get(key) is True for key in _SUBSCOPE_RULE_KEYS):
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
    # Output `capa -j` thật dùng khóa ``attack``; ``att&ck`` chỉ là alias pydantic
    # và chỉ xuất hiện ở tài liệu in theo alias — fallback chỉ khi thiếu ``attack``.
    key = _ATTACK_KEY if _ATTACK_KEY in meta else _ATTACK_KEY_LEGACY
    entries = meta.get(key, [])
    if entries is None:
        # Phòng producer ghi null thay vì [] cho rule không có mapping.
        return []
    if not isinstance(entries, list):
        raise CapaStructureError(f"rule {rule_name!r}: {key!r} phải là một mảng")
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
            f"rule {rule_name!r}: entry {_ATTACK_KEY!r} phải là object hoặc chuỗi canonical"
        )
    if not technique_id:
        raise CapaStructureError(
            f"rule {rule_name!r}: entry {_ATTACK_KEY!r} thiếu định danh kỹ thuật 'id'"
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
        raise CapaStructureError(f"rule {rule_name!r}: '{_ATTACK_KEY}[].{key}' phải là string")
    return value


def _parse_canonical_attack(
    rule_name: object, spec: str
) -> tuple[str, str, str, str]:
    """Parse dạng canonical của YAML rule: ``Tactic::Technique::Subtechnique [Identifier]``.

    Đây là từ vựng **YAML rule nguồn** (``AttackSpec.from_str``), không phải dạng
    mà bất kỳ phiên bản capa nào ghi ra JSON — giữ như dung sai robustness.

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
