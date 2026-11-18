"""Exclusion linter: flags exclusions that are broader or riskier than needed.

None of these findings blocks saving (``require_reason`` aside); they show up
next to the exclusion and on the dashboard. Each finding has a ``code`` the UI
translates and a level: ``error`` (almost certainly a mistake), ``warning``
(risky, worth a second look) or ``info``.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta

from ..seclang import catalog
from ..seclang.model import Exclusion, Issue
from .ids import IdPolicy, in_group_blocks


def _selector_ids(ex: Exclusion) -> list[int]:
    out = []
    if ex.selector_type != "id":
        return out
    for s in ex.selectors:
        lo = s.split("-")[0]
        if lo.isdigit():
            out.append(int(lo))
    return out


def lint(ex: Exclusion, policy: IdPolicy | None = None, group_blocks: list[int] | None = None,
         require_reason: bool = False, expiry_warning_days: int = 14,
         today: date | None = None) -> list[Issue]:
    out: list[Issue] = []
    today = today or date.today()

    def add(code: str, level: str, field: str = "", **params):
        out.append(Issue(field, code, level, params))

    if not ex.reason.strip():
        add("no_reason", "error" if require_reason else "info", "reason")

    if ex.expires_at:
        try:
            exp = datetime.fromisoformat(ex.expires_at[:10]).date()
            if exp < today:
                add("expired", "warning", "expires_at", date=exp.isoformat())
            elif exp <= today + timedelta(days=expiry_warning_days):
                add("expires_soon", "info", "expires_at", date=exp.isoformat())
        except ValueError:
            add("invalid_date", "error", "expires_at")

    if ex.scope == "raw":
        add("raw_unchecked", "info")
        return out

    if ex.verbatim:
        add("verbatim_import", "info")

    for rid in _selector_ids(ex):
        if catalog.is_scoring_rule(rid):
            add("targets_scoring_rule", "error", "selectors", rule=rid)

    if ex.action == "engine_mode":
        add("engine_off" if ex.engine_mode == "Off" else "engine_detection_only",
            "warning", "engine_mode")

    if ex.scope == "global" and ex.action == "remove_rule":
        add("global_rule_removal", "warning", "scope")

    if ex.action in ("remove_rule", "remove_target") and ex.selector_type == "tag":
        add("removes_by_tag", "info", "selectors")

    if ex.action == "remove_rule" and ex.scope == "conditional":
        add("could_remove_target", "info", "action")

    if ex.scope == "conditional":
        paths = [c for c in ex.conditions
                 if catalog.variable_base(c.variable) in ("REQUEST_URI", "REQUEST_FILENAME")
                 and not c.negate]
        if len(ex.conditions) == 1 and paths and paths[0].operator in ("beginsWith", "contains", "rx") \
                and paths[0].value.strip() in ("/", "", ".*", "^/", "^/.*"):
            add("matches_everything", "warning", "conditions")
        if any(catalog.variable_base(c.variable) == "REQUEST_URI" and c.operator in ("streq", "endsWith")
               for c in ex.conditions):
            add("request_uri_has_query", "info", "conditions")
        if ex.effective_phase() == 2:
            phase1 = [r for r in _selector_ids(ex) if r in catalog.PHASE1_RULES]
            if phase1:
                add("phase2_cannot_remove_phase1", "warning", "conditions", rules=phase1)

    if ex.rule_id:   # 0 is the placeholder used by the form preview
        owner = catalog.reserved_owner(ex.rule_id)
        if owner:
            add("rule_id_reserved", "warning", "rule_id", owner=owner, rule=ex.rule_id)
        elif policy and group_blocks is not None and not in_group_blocks(policy, group_blocks, ex.rule_id):
            add("rule_id_outside_group", "info", "rule_id", rule=ex.rule_id)
    return out


def worst(issues: list[Issue]) -> str | None:
    order = {"error": 3, "warning": 2, "info": 1}
    best = None
    for i in issues:
        if best is None or order[i.level] > order[best]:
            best = i.level
    return best
