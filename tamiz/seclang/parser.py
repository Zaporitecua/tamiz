"""Recognise rule exclusions in existing configuration.

The parser reads configuration text and classifies every directive:

* ``exclusion`` items that Tamiz can represent with its structured model
  (``Exclusion`` with scope ``conditional`` or ``global``);
* ``exclusion`` items that are exclusions in spirit (they use ``ctl:``, an
  ``allow`` action or a ``SecRuleRemove*``/``SecRuleUpdate*`` directive) but do
  not fit the model; they become ``raw`` exclusions carried verbatim;
* ``other`` directives that are not exclusions at all.

Recognition is deliberately strict. When in doubt an item is classified as
raw, never forced into the structured model, because a wrong structured
reading followed by a re-render would silently change what the WAF does.
Imported structured items keep their source text anyway (see model.py).

Chained rules are grouped with their chain starter: a ``SecRule`` with the
``chain`` action swallows the following ``SecRule`` directives until one
without ``chain``. Comments and blank lines in between belong to the chain.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import catalog
from .lexer import Action, LexError, Statement, lex, parse_actions
from .model import Condition, Exclusion, ID_SELECTOR_RE, TARGET_VAR_RE

TAMIZ_COMMENT_RE = re.compile(r"^#\s*Tamiz\s+#\d+:?\s*")
TAMIZ_HEADER_HINTS = ("Managed by Tamiz", "tamiz:begin", "tamiz:end")


@dataclass
class Item:
    kind: str                         # "exclusion" | "other" | "comment" | "blank"
    start: int
    end: int
    text: str
    exclusion: Exclusion | None = None
    raw_reason: str | None = None     # why an exclusion could not be structured
    ids: list[int] = field(default_factory=list)
    comment: str = ""                 # attached comment (candidate reason)
    comment_start: int | None = None  # first line of the attached comment
    directive: str = ""               # first directive name


@dataclass
class ParseResult:
    items: list[Item]
    errors: list[dict]
    warnings: list[dict]

    @property
    def exclusions(self) -> list[Item]:
        return [i for i in self.items if i.kind == "exclusion"]

    @property
    def others(self) -> list[Item]:
        return [i for i in self.items if i.kind == "other"]


class NotRepresentable(Exception):
    pass


def _actions_of(st: Statement) -> list[Action]:
    if st.lname == "secrule" and len(st.args) >= 3:
        return parse_actions(st.args[2])
    if st.lname == "secaction" and len(st.args) >= 1:
        return parse_actions(st.args[0])
    return []


def _rule_id(actions: list[Action]) -> int | None:
    for a in actions:
        if a.name == "id" and a.value is not None and a.value.strip().isdigit():
            return int(a.value.strip())
    return None


def _is_exclusion_like(chain: list[Statement]) -> bool:
    for st in chain:
        for a in _actions_of(st):
            if a.name == "ctl" and a.value:
                kind = a.value.split("=", 1)[0].strip().lower()
                if kind in catalog.CTL_KINDS:
                    return True
            if a.name == "allow":
                return True
    return False


def _parse_operator(op: str) -> tuple[str, str, bool]:
    negate = op.startswith("!")
    s = op[1:] if negate else op
    if s.startswith("@"):
        name, _, value = s[1:].partition(" ")
        return name, value.lstrip(), negate
    return "rx", s, negate


def _phase(value: str | None) -> int | None:
    if value is None:
        return None
    v = value.strip().lower()
    names = {"request": 2, "response": 4, "logging": 5}
    if v in names:
        return names[v]
    return int(v) if v.isdigit() else None


def structure_chain(chain: list[Statement]) -> Exclusion:
    """Turn a SecRule chain into a conditional Exclusion or raise."""
    links = [st for st in chain if st.kind == "directive"]
    conditions: list[Condition] = []
    starter_actions: list[Action] = []
    ctl: list[tuple[str, str]] = []
    for k, st in enumerate(links):
        if st.lname != "secrule":
            raise NotRepresentable("chain_contains_non_secrule")
        if len(st.args) < 2 or len(st.args) > 3:
            raise NotRepresentable("unexpected_argument_count")
        variable = st.args[0]
        op_name, value, negate = _parse_operator(st.args[1])
        canonical = catalog.OPERATORS_LOWER.get(op_name.lower())
        if canonical is None:
            raise NotRepresentable(f"operator_{op_name}")
        actions = parse_actions(st.args[2]) if len(st.args) == 3 else []
        transforms: list[str] = []
        last = k == len(links) - 1
        for a in actions:
            if a.name == "t":
                if a.value and a.value.lower() != "none":
                    transforms.append(a.value)
                continue
            if a.name == "chain":
                if last:
                    raise NotRepresentable("chain_on_last_link")
                continue
            if a.name == "ctl":
                if not last:
                    raise NotRepresentable("ctl_before_end_of_chain")
                key, _, param = (a.value or "").partition("=")
                ctl.append((key.strip().lower(), param.strip()))
                continue
            if k == 0 and a.name in {"id", "phase", "pass"} | catalog.LOG_ACTIONS | catalog.METADATA_ACTIONS:
                starter_actions.append(a)
                continue
            raise NotRepresentable(f"action_{a.name}")
        if not last and not any(a.name == "chain" for a in actions):
            raise NotRepresentable("broken_chain")
        conditions.append(Condition(variable, canonical, value, negate, transforms))

    names = {a.name for a in starter_actions}
    if "pass" not in names:
        raise NotRepresentable("not_a_pass_rule")
    rule_id = _rule_id(starter_actions)
    if rule_id is None:
        raise NotRepresentable("missing_id")
    phase = None
    for a in starter_actions:
        if a.name == "phase":
            phase = _phase(a.value)
    if phase not in (1, 2):
        raise NotRepresentable("unsupported_phase")
    if not ctl:
        raise NotRepresentable("no_ctl")

    kinds = {catalog.CTL_KINDS.get(k) for k, _ in ctl}
    if None in kinds or len(kinds) != 1:
        raise NotRepresentable("mixed_ctl")
    action, selector_type = kinds.pop()
    ex = Exclusion(scope="conditional", action=action, selector_type=selector_type,
                   conditions=conditions, rule_id=rule_id, phase=phase)
    ex.log = ("log" in names or "auditlog" in names) and "nolog" not in names
    ex.extra_actions = [a.raw for a in starter_actions if a.name in catalog.METADATA_ACTIONS]

    if action == "engine_mode":
        if len(ctl) != 1 or ctl[0][1] not in catalog.ENGINE_MODES:
            raise NotRepresentable("engine_mode_value")
        ex.engine_mode = ctl[0][1]
        ex.selector_type = None
        return ex
    if action == "remove_rule":
        selectors: list[str] = []
        for _, param in ctl:
            for tok in param.split():
                if selector_type == "id" and not ID_SELECTOR_RE.match(tok):
                    raise NotRepresentable("bad_rule_id")
                if tok not in selectors:
                    selectors.append(tok)
        ex.selectors = selectors
        return ex
    pairs: list[tuple[str, str]] = []
    for _, param in ctl:
        sel, sep, var = param.partition(";")
        if not sep or not sel.strip() or not var.strip():
            raise NotRepresentable("bad_target")
        pairs.append((sel.strip(), var.strip()))
    sels = list(dict.fromkeys(p[0] for p in pairs))
    vars_ = list(dict.fromkeys(p[1] for p in pairs))
    if pairs != [(s, v) for s in sels for v in vars_]:
        raise NotRepresentable("targets_not_a_product")
    for s in sels:
        if selector_type == "id" and not ID_SELECTOR_RE.match(s):
            raise NotRepresentable("bad_rule_id")
    for v in vars_:
        if not TARGET_VAR_RE.match(v):
            raise NotRepresentable("bad_variable")
    ex.selectors, ex.variables = sels, vars_
    return ex


def structure_global(st: Statement) -> Exclusion:
    name = st.lname
    if name == "secruleremovebyid":
        if not st.args or not all(ID_SELECTOR_RE.match(a) for a in st.args):
            raise NotRepresentable("bad_rule_id")
        return Exclusion(scope="global", action="remove_rule", selector_type="id",
                         selectors=list(st.args))
    if name == "secruleremovebytag":
        if len(st.args) != 1:
            raise NotRepresentable("unexpected_argument_count")
        return Exclusion(scope="global", action="remove_rule", selector_type="tag",
                         selectors=[st.args[0]])
    if name in ("secruleupdatetargetbyid", "secruleupdatetargetbytag"):
        if len(st.args) != 2:
            raise NotRepresentable("unexpected_argument_count")
        parts = [p.strip() for p in st.args[1].split("|") if p.strip()]
        if not parts or not all(p.startswith("!") for p in parts):
            raise NotRepresentable("adds_targets")
        variables = [p[1:] for p in parts]
        if not all(TARGET_VAR_RE.match(v) for v in variables):
            raise NotRepresentable("bad_variable")
        selector_type = "id" if name.endswith("byid") else "tag"
        if selector_type == "id" and not re.match(r"^\d+$", st.args[0]):
            raise NotRepresentable("bad_rule_id")
        return Exclusion(scope="global", action="remove_target", selector_type=selector_type,
                         selectors=[st.args[0]], variables=variables)
    raise NotRepresentable("unsupported_directive")


GLOBAL_EXCLUSION_DIRECTIVES = {
    "secruleremovebyid", "secruleremovebytag", "secruleremovebymsg",
    "secruleupdatetargetbyid", "secruleupdatetargetbytag", "secruleupdatetargetbymsg",
    "secruleupdateactionbyid",
}


def _attached_comment(statements: list[Statement], index: int) -> tuple[str, int | None]:
    """Comment lines immediately above statement ``index`` (no blank line)."""
    lines: list[str] = []
    first = None
    j = index - 1
    while j >= 0 and statements[j].kind == "comment":
        text = statements[j].text.strip()
        if any(h in text for h in TAMIZ_HEADER_HINTS):
            break
        lines.insert(0, text)
        first = statements[j].start
        j -= 1
    # A comment block that starts at the top of the file is usually the file's
    # own header; only its last line describes the rule below it.
    # (A comment written by Tamiz itself, "# Tamiz #N: ...", is never a header.)
    if first == 0 and len(lines) > 1 and not any(TAMIZ_COMMENT_RE.match(ln) for ln in lines):
        lines = lines[-1:]
        first = statements[index - 1].start
    cleaned = []
    for ln in lines:
        ln = TAMIZ_COMMENT_RE.sub("", ln) if TAMIZ_COMMENT_RE.match(ln) else ln.lstrip("#").strip()
        if ln.lower().startswith("ref:") or ln.lower().startswith("expires:"):
            continue
        if ln:
            cleaned.append(ln)
    return " ".join(cleaned)[:500], first


def parse_config(text: str) -> ParseResult:
    errors: list[dict] = []
    warnings: list[dict] = []
    try:
        statements = lex(text)
    except LexError as e:
        return ParseResult([], [{"line": e.line + 1, "code": "lex_error", "detail": e.reason}], [])

    items: list[Item] = []
    i = 0
    while i < len(statements):
        st = statements[i]
        if st.kind != "directive":
            if st.kind == "comment" and st.text.rstrip().endswith("\\"):
                warnings.append({"line": st.start + 1, "code": "comment_with_continuation"})
            items.append(Item(st.kind, st.start, st.end, st.text))
            i += 1
            continue

        chain = [st]
        last_idx = i
        if st.lname == "secrule":
            acts = _actions_of(st)
            j = i
            while any(a.name == "chain" for a in acts):
                j += 1
                pending: list[Statement] = []
                while j < len(statements) and statements[j].kind != "directive":
                    pending.append(statements[j])
                    j += 1
                if j >= len(statements) or statements[j].lname != "secrule":
                    errors.append({"line": st.start + 1, "code": "broken_chain"})
                    break
                chain.extend(pending)
                chain.append(statements[j])
                last_idx = j
                acts = _actions_of(statements[j])
        start, end = chain[0].start, chain[-1].end
        text_block = "\n".join(s.text for s in chain)
        comment, comment_start = _attached_comment(statements, i)
        ids = [rid for s in chain for rid in [_rule_id(_actions_of(s))] if rid is not None]
        item = Item("other", start, end, text_block, ids=ids, comment=comment,
                    comment_start=comment_start, directive=st.name)

        if st.lname == "secrule" and _is_exclusion_like(chain):
            item.kind = "exclusion"
            try:
                ex = structure_chain(chain)
                item.exclusion = ex
            except NotRepresentable as e:
                item.raw_reason = str(e)
        elif st.lname == "secaction" and _is_exclusion_like(chain):
            item.kind = "exclusion"
            item.raw_reason = "secaction"
        elif st.lname in GLOBAL_EXCLUSION_DIRECTIVES:
            item.kind = "exclusion"
            try:
                item.exclusion = structure_global(st)
            except NotRepresentable as e:
                item.raw_reason = str(e)
        items.append(item)
        i = last_idx + 1
    return ParseResult(items, errors, warnings)
