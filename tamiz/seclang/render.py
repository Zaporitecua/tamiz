"""Deterministic rendering of exclusions into SecLang.

Determinism matters: Tamiz compares what it would write against what is on the
server to decide whether a file is up to date. Nothing in the output depends
on the clock, so the same database state always renders the same bytes.
"""
from __future__ import annotations

import re

from . import catalog
from .model import Exclusion

STYLES = ("crs", "compact")

BLOCK_BEGIN = "# ---- tamiz:begin group={slug} ----"
BLOCK_END = "# ---- tamiz:end group={slug} ----"


def _quote(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'


def _clean_comment(s: str) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]", " ", s or "").strip()
    return s


def format_rule(variables: str, operator: str, actions: list[str], indent: int, style: str) -> str:
    pad = " " * indent
    head = f"{pad}SecRule {variables} {_quote(operator)} \\"
    if style == "compact":
        return head + "\n" + pad + "    " + _quote(",".join(actions))
    inner = pad + "    "
    lines = [head]
    for i, a in enumerate(actions):
        a = a.replace('"', '\\"')
        prefix = '"' if i == 0 else ""
        if i < len(actions) - 1:
            lines.append(f"{inner}{prefix}{a},\\")
        else:
            lines.append(f"{inner}{prefix}{a}\"")
    return "\n".join(lines)


def operator_string(op: str, value: str, negate: bool) -> str:
    s = ("!" if negate else "") + "@" + op
    if value != "":
        s += " " + value
    return s


def ctl_actions(ex: Exclusion) -> list[str]:
    if ex.action == "engine_mode":
        return [f"ctl:ruleEngine={ex.engine_mode}"]
    name = catalog.CTL_NAMES[(ex.action, ex.selector_type)]
    if ex.action == "remove_rule":
        return [f"ctl:{name}={s}" for s in ex.selectors]
    return [f"ctl:{name}={s};{v}" for s in ex.selectors for v in ex.variables]


def render_conditional(ex: Exclusion, style: str = "crs") -> str:
    rules = []
    n = len(ex.conditions)
    for k, c in enumerate(ex.conditions):
        actions: list[str] = []
        if k == 0:
            actions += [f"id:{ex.rule_id}", f"phase:{ex.effective_phase()}", "pass"]
        actions.append("t:none")
        actions += [f"t:{t}" for t in c.transforms]
        if k == 0:
            actions.append("log" if ex.log else "nolog")
            actions += ex.extra_actions
        if k < n - 1:
            actions.append("chain")
        else:
            actions += ctl_actions(ex)
        rules.append(format_rule(c.variable, operator_string(c.operator, c.value, c.negate),
                                 actions, 4 * k, style))
    return "\n".join(rules)


def render_global(ex: Exclusion) -> str:
    if ex.action == "remove_rule" and ex.selector_type == "id":
        return "SecRuleRemoveById " + " ".join(ex.selectors)
    if ex.action == "remove_rule" and ex.selector_type == "tag":
        return "\n".join(f"SecRuleRemoveByTag {_quote(t)}" for t in ex.selectors)
    targets = _quote("|".join("!" + v for v in ex.variables))
    if ex.selector_type == "id":
        return "\n".join(f"SecRuleUpdateTargetById {s} {targets}" for s in ex.selectors)
    return "\n".join(f"SecRuleUpdateTargetByTag {_quote(s)} {targets}" for s in ex.selectors)


def render_directives(ex: Exclusion, style: str = "crs") -> str:
    """Only the SecLang directives, without the explanatory comment."""
    if ex.scope == "raw":
        return normalize_text(ex.raw_text or "")
    if ex.verbatim and ex.source_text:
        return normalize_text(ex.source_text)
    if ex.scope == "conditional":
        return render_conditional(ex, style)
    return render_global(ex)


def comment_lines(ex: Exclusion) -> list[str]:
    head = f"# Tamiz #{ex.id}" if ex.id is not None else "# Tamiz (new)"
    reason = _clean_comment(ex.reason)
    lines = [head + (f": {reason}" if reason else "")]
    ref = _clean_comment(ex.reference)
    if ref:
        lines.append(f"# Ref: {ref}")
    if ex.expires_at:
        lines.append(f"# Expires: {_clean_comment(ex.expires_at)[:10]}")
    return lines


def render_exclusion(ex: Exclusion, style: str = "crs") -> str:
    return "\n".join(comment_lines(ex) + [render_directives(ex, style)])


def normalize_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip() for ln in text.split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def sort_key(ex: Exclusion) -> tuple:
    if ex.scope == "conditional" and ex.rule_id is not None:
        return (0, ex.rule_id, ex.id or 0)
    return (1, ex.id or 0, 0)


PLACEMENT_TEXT = {
    "before": "before the CRS rules (runtime exclusions)",
    "after": "after the CRS rules (configure-time exclusions)",
}


def render_file(group: dict, placement: str, exclusions: list[Exclusion], style: str = "crs") -> str:
    """Content of a file owned entirely by Tamiz."""
    blocks = group.get("id_ranges") or ""
    head = [
        "# Managed by Tamiz. Do not edit this file by hand: changes made here are",
        "# reported as drift and replaced on the next apply. Edit the exclusions in",
        "# Tamiz instead.",
        "#",
        f"# Group:     {group['slug']} ({_clean_comment(group['name'])})",
        f"# Placement: {PLACEMENT_TEXT[placement]}",
    ]
    if blocks:
        head.append(f"# Rule IDs:  {blocks}")
    body = [render_exclusion(ex, style) for ex in sorted(exclusions, key=sort_key)]
    return "\n".join(head) + "\n\n" + "\n\n".join(body) + "\n"


def render_block(group: dict, placement: str, exclusions: list[Exclusion], style: str = "crs") -> str:
    """A managed block to be placed inside a file Tamiz does not own."""
    slug = group["slug"]
    blocks = group.get("id_ranges") or ""
    lines = [
        BLOCK_BEGIN.format(slug=slug),
        f"# Managed by Tamiz: group {slug}" + (f", rule IDs {blocks}" if blocks else "")
        + ". Do not edit inside this block.",
        "",
    ]
    body = [render_exclusion(ex, style) for ex in sorted(exclusions, key=sort_key)]
    lines.append("\n\n".join(body))
    lines.append(BLOCK_END.format(slug=slug))
    return "\n".join(lines)
