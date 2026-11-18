"""The exclusion model shared by the renderer, the parser and the database.

An exclusion is one of three shapes:

* ``conditional``: a runtime exclusion. Tamiz renders it as a ``SecRule`` (a
  chain when there are several conditions) with ``ctl:`` actions. It must be
  loaded *before* the CRS rules.
* ``global``: a configure-time exclusion (``SecRuleRemoveById``,
  ``SecRuleUpdateTargetById`` ...). It applies to every request and must be
  loaded *after* the CRS rules, because it edits rules that already exist.
* ``raw``: SecLang text the user maintains by hand. Tamiz carries it through
  untouched; the user chooses where it is loaded.

Imported rules keep their original text in ``source_text`` and are rendered
verbatim (``verbatim=True``) until someone edits them in Tamiz. That way an
import never changes the meaning of a rule, even in details the structured
model does not capture.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from . import catalog

SCOPES = ("conditional", "global", "raw")
ACTIONS = ("remove_rule", "remove_target", "engine_mode")
SELECTOR_TYPES = ("id", "tag")
PLACEMENTS = ("before", "after")

ID_SELECTOR_RE = re.compile(r"^\d{1,9}(-\d{1,9})?$")
TAG_RE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,128}$")
# A variable for target removal: COLLECTION or COLLECTION:key or
# COLLECTION:/regex/. Commas, quotes, pipes and whitespace would break the
# action list, so they are rejected.
TARGET_VAR_RE = re.compile(r"^[A-Z_]{2,40}(:(/[^,\"\s|]+/|[^,\"\s|;/][^,\"\s|;]*))?$")
COND_VAR_RE = re.compile(r"^!?&?[A-Z_]{2,40}(:[^\"\s,|]+)?(\|!?&?[A-Z_]{2,40}(:[^\"\s,|]+)?)*$")
TRANSFORM_RE = re.compile(r"^[A-Za-z0-9]{2,40}$")


@dataclass
class Condition:
    variable: str
    operator: str
    value: str = ""
    negate: bool = False
    transforms: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Condition":
        return cls(
            variable=str(d.get("variable", "")).strip(),
            operator=str(d.get("operator", "")).strip(),
            value=str(d.get("value", "")),
            negate=bool(d.get("negate", False)),
            transforms=[str(t).strip() for t in d.get("transforms") or [] if str(t).strip()],
        )


@dataclass
class Exclusion:
    id: int | None = None
    group_id: int | None = None
    scope: str = "conditional"
    action: str | None = "remove_rule"
    selector_type: str | None = "id"
    selectors: list[str] = field(default_factory=list)
    variables: list[str] = field(default_factory=list)
    engine_mode: str | None = None
    conditions: list[Condition] = field(default_factory=list)
    phase: int | None = None          # None = chosen automatically
    log: bool = False
    extra_actions: list[str] = field(default_factory=list)
    rule_id: int | None = None
    raw_text: str | None = None
    placement: str | None = None      # only meaningful for raw exclusions
    source_text: str | None = None
    verbatim: bool = False
    reason: str = ""
    reference: str = ""
    expires_at: str | None = None
    enabled: bool = True
    origin: str = "ui"

    # ----------------------------------------------------------- helpers --
    def effective_placement(self) -> str:
        if self.scope == "conditional":
            return "before"
        if self.scope == "global":
            return "after"
        return self.placement or "before"

    def effective_phase(self) -> int:
        if self.phase in (1, 2):
            return self.phase
        return 2 if catalog.needs_phase2([c.variable for c in self.conditions]) else 1

    def to_dict(self) -> dict:
        d = asdict(self)
        d["placement"] = self.effective_placement()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Exclusion":
        ex = cls()
        for key in ("id", "group_id", "scope", "action", "selector_type", "engine_mode",
                    "phase", "rule_id", "raw_text", "placement", "source_text",
                    "expires_at", "origin"):
            if key in d:
                setattr(ex, key, d[key])
        for key in ("reason", "reference"):
            if key in d and d[key] is not None:
                setattr(ex, key, str(d[key]))
        for key in ("log", "verbatim", "enabled"):
            if key in d and d[key] is not None:
                setattr(ex, key, bool(d[key]))
        ex.selectors = [str(s).strip() for s in d.get("selectors") or [] if str(s).strip()]
        ex.variables = [str(s).strip() for s in d.get("variables") or [] if str(s).strip()]
        ex.extra_actions = [str(s).strip() for s in d.get("extra_actions") or [] if str(s).strip()]
        ex.conditions = [Condition.from_dict(c) for c in d.get("conditions") or []]
        if ex.phase in ("", 0):
            ex.phase = None
        if ex.phase is not None:
            ex.phase = int(ex.phase)
        return ex


@dataclass
class Issue:
    """A validation or lint finding. ``code`` is translated by the UI."""
    field: str
    code: str
    level: str = "error"          # error | warning | info
    params: dict = field(default_factory=dict)


def validate(ex: Exclusion) -> list[Issue]:
    """Structural validation. Returns errors that make the exclusion unsafe
    or impossible to render. Policy checks live in ``core.lint``."""
    issues: list[Issue] = []

    def err(f: str, code: str, **params):
        issues.append(Issue(f, code, "error", params))

    if ex.scope not in SCOPES:
        err("scope", "invalid_scope")
        return issues

    if len(ex.reason) > 500:
        err("reason", "too_long", max=500)
    if "\n" in ex.reason or "\r" in ex.reason:
        err("reason", "single_line")
    if len(ex.reference) > 300:
        err("reference", "too_long", max=300)

    if ex.scope == "raw":
        text = (ex.raw_text or "").strip()
        if not text:
            err("raw_text", "required")
        if ex.placement not in PLACEMENTS:
            err("placement", "invalid_placement")
        return issues

    if ex.verbatim:
        # Imported text is validated by the parser that produced it.
        return issues

    if ex.action not in ACTIONS:
        err("action", "invalid_action")
        return issues

    if ex.action == "engine_mode":
        if ex.scope != "conditional":
            err("action", "engine_mode_needs_condition")
        if ex.engine_mode not in catalog.ENGINE_MODES:
            err("engine_mode", "invalid_engine_mode")
    else:
        if ex.selector_type not in SELECTOR_TYPES:
            err("selector_type", "invalid_selector_type")
        if not ex.selectors:
            err("selectors", "required")
        for s in ex.selectors:
            if ex.selector_type == "id":
                if not ID_SELECTOR_RE.match(s):
                    err("selectors", "invalid_rule_id", value=s)
                elif "-" in s:
                    lo, hi = (int(x) for x in s.split("-"))
                    if lo >= hi:
                        err("selectors", "invalid_range", value=s)
                    if ex.scope == "global" and ex.action == "remove_target":
                        err("selectors", "range_not_allowed_here", value=s)
            elif ex.selector_type == "tag" and not TAG_RE.match(s):
                err("selectors", "invalid_tag", value=s)
        if len(set(ex.selectors)) != len(ex.selectors):
            err("selectors", "duplicated")

    if ex.action == "remove_target":
        if not ex.variables:
            err("variables", "required")
        for v in ex.variables:
            if not TARGET_VAR_RE.match(v):
                err("variables", "invalid_variable", value=v)
        if len(set(ex.variables)) != len(ex.variables):
            err("variables", "duplicated")

    if ex.scope == "conditional":
        if not ex.conditions:
            err("conditions", "required")
        if len(ex.conditions) > 8:
            err("conditions", "too_many", max=8)
        for i, c in enumerate(ex.conditions):
            f = f"conditions.{i}"
            if not COND_VAR_RE.match(c.variable):
                err(f + ".variable", "invalid_variable", value=c.variable)
            if c.operator not in catalog.OPERATORS:
                err(f + ".operator", "invalid_operator", value=c.operator)
            if "\n" in c.value or "\r" in c.value:
                err(f + ".value", "single_line")
            if c.value.endswith("\\"):
                err(f + ".value", "trailing_backslash")
            if c.value.strip() == "" and c.operator not in ("eq", "ge", "gt", "le", "lt"):
                err(f + ".value", "required")
            if c.operator == "rx":
                try:
                    re.compile(c.value)
                except re.error:
                    issues.append(Issue(f + ".value", "regex_not_python", "warning"))
            if c.operator == "ipMatch":
                for part in c.value.split(","):
                    if not re.match(r"^[0-9a-fA-F:.]+(/\d{1,3})?$", part.strip()):
                        err(f + ".value", "invalid_ip", value=part.strip())
            for t in c.transforms:
                if not TRANSFORM_RE.match(t) or t.lower() == "none":
                    err(f + ".transforms", "invalid_transform", value=t)
        if ex.phase not in (None, 1, 2):
            err("phase", "invalid_phase")
        if ex.phase == 1 and catalog.needs_phase2([c.variable for c in ex.conditions]):
            err("phase", "phase1_needs_headers_only")
        for a in ex.extra_actions:
            name = a.split(":", 1)[0].strip().lower()
            if name not in catalog.METADATA_ACTIONS:
                err("extra_actions", "invalid_extra_action", value=a)
    else:
        if ex.conditions:
            err("conditions", "global_has_no_conditions")
    return issues
