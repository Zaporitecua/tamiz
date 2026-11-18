"""Tests for the SecLang core: lexer, parser, renderer and managed blocks.

Several cases are mistakes that are easy to make when reading or writing
SecLang: a lost negation, ``ctl:`` in the wrong link of a chain, an unknown
action rewritten instead of kept.
"""
import pytest

from tamiz.seclang import blocks, parser, render
from tamiz.seclang.lexer import lex, parse_actions, split_actions
from tamiz.seclang.model import Condition, Exclusion, validate


def roundtrip(ex: Exclusion, style="crs") -> Exclusion:
    text = render.render_directives(ex, style)
    result = parser.parse_config(text)
    assert not result.errors, result.errors
    items = result.exclusions
    assert len(items) == 1, text
    assert items[0].raw_reason is None, (items[0].raw_reason, text)
    return items[0].exclusion


def cond(var, op, val, negate=False, transforms=None):
    return Condition(var, op, val, negate, transforms or [])


# ------------------------------------------------------------------ lexer --

def test_lexer_joins_continuations_and_keeps_source():
    text = 'SecRule REQUEST_URI "@beginsWith /x" \\\n    "id:1,\\\n    phase:1,pass"\n# c\n\n'
    sts = lex(text)
    assert [s.kind for s in sts] == ["directive", "comment", "blank"]
    d = sts[0]
    assert d.start == 0 and d.end == 2
    assert d.args == ["REQUEST_URI", "@beginsWith /x", "id:1,    phase:1,pass"]
    assert d.text == 'SecRule REQUEST_URI "@beginsWith /x" \\\n    "id:1,\\\n    phase:1,pass"'


def test_lexer_escaped_quote_and_literal_backslash():
    sts = lex(r'SecRule ARGS "@rx a\"b\d" "id:1"')
    assert sts[0].args[1] == r'@rx a"b\d'


def test_split_actions_respects_single_quotes():
    assert split_actions("id:1,msg:'a, b',tag:'x'") == ["id:1", "msg:'a, b'", "tag:'x'"]
    acts = parse_actions("id:1, phase:1, pass, nolog, ctl:ruleRemoveById=200002")
    assert [a.name for a in acts] == ["id", "phase", "pass", "nolog", "ctl"]
    assert acts[-1].value == "ruleRemoveById=200002"


# ----------------------------------------------------------------- parser --

def test_compact_actions_format_is_recognised():
    # Actions on one line separated by ", ", as many hand-written rules use.
    text = ('SecRule REQUEST_URI "@beginsWith /shop/api" \\\n'
            '    "id:1009502, phase:1, pass, nolog, ctl:ruleRemoveById=200002"\n')
    item = parser.parse_config(text).exclusions[0]
    ex = item.exclusion
    assert ex.scope == "conditional" and ex.action == "remove_rule"
    assert ex.rule_id == 1009502 and ex.selectors == ["200002"]
    assert ex.conditions[0].operator == "beginsWith"
    assert ex.conditions[0].value == "/shop/api"


def test_negated_operator_survives_roundtrip():
    # A classic bug: "!@eq" losing its negation when re-rendered.
    ex = Exclusion(scope="conditional", action="remove_rule", selector_type="id",
                   selectors=["942100"], rule_id=10001,
                   conditions=[cond("REQUEST_FILENAME", "beginsWith", "/api"),
                               cond("&ARGS:token", "eq", "0", negate=True)])
    back = roundtrip(ex)
    assert back.conditions[1].negate is True
    assert back.conditions[1].operator == "eq"
    assert back.conditions[1].variable == "&ARGS:token"


def test_chain_is_one_item_and_ctl_lives_in_last_link():
    ex = Exclusion(scope="conditional", action="remove_target", selector_type="id",
                   selectors=["942100", "942200"], variables=["ARGS:q", "ARGS:filter"],
                   rule_id=10002,
                   conditions=[cond("REQUEST_FILENAME", "streq", "/search"),
                               cond("REQUEST_METHOD", "streq", "POST"),
                               cond("REQUEST_HEADERS:Host", "streq", "shop.example.com",
                                    transforms=["lowercase"])])
    text = render.render_directives(ex)
    # ctl only in the last rule of the chain
    rules = text.split("SecRule ")[1:]
    assert all("ctl:" not in r for r in rules[:-1])
    assert "ctl:ruleRemoveTargetById=942100;ARGS:q" in rules[-1]
    back = roundtrip(ex)
    assert back.selectors == ex.selectors and back.variables == ex.variables
    assert [c.variable for c in back.conditions] == [c.variable for c in ex.conditions]
    assert back.conditions[2].transforms == ["lowercase"]


def test_ctl_in_chain_starter_is_kept_raw():
    # Valid SecLang, but the ctl fires as soon as the first condition matches.
    text = ('SecRule REQUEST_FILENAME "@beginsWith /a" "id:5,phase:1,pass,nolog,'
            'ctl:ruleRemoveById=942100,chain"\n'
            '    SecRule REQUEST_METHOD "@streq POST" "t:none"\n')
    item = parser.parse_config(text).exclusions[0]
    assert item.exclusion is None
    assert item.raw_reason == "ctl_before_end_of_chain"
    assert item.ids == [5]


def test_unknown_action_makes_item_raw_not_structured():
    text = 'SecRule REQUEST_URI "@beginsWith /a" "id:6,phase:1,pass,nolog,setvar:tx.x=1,ctl:ruleRemoveById=1"'
    item = parser.parse_config(text).exclusions[0]
    assert item.exclusion is None and item.raw_reason == "action_setvar"


def test_deny_rule_is_not_an_exclusion():
    text = 'SecRule REMOTE_ADDR "@ipMatch 1.2.3.4" "id:7,phase:1,deny,status:403"'
    res = parser.parse_config(text)
    assert not res.exclusions and res.others[0].ids == [7]


def test_allow_rule_is_an_exclusion_kept_raw():
    text = 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:8,phase:1,allow,nolog"'
    item = parser.parse_config(text).exclusions[0]
    assert item.exclusion is None


def test_global_directives():
    text = ('SecRuleRemoveById 942100 942200-942299\n'
            'SecRuleUpdateTargetById 942100 "!ARGS:password|!ARGS:pwd"\n'
            'SecRuleUpdateTargetByTag "attack-sqli" "!REQUEST_COOKIES:session"\n'
            'SecRuleUpdateTargetById 942100 "ARGS:extra"\n')
    items = parser.parse_config(text).exclusions
    assert items[0].exclusion.selectors == ["942100", "942200-942299"]
    assert items[1].exclusion.variables == ["ARGS:password", "ARGS:pwd"]
    assert items[2].exclusion.selector_type == "tag"
    assert items[3].exclusion is None  # adds a target: not an exclusion we model


def test_attached_comment_becomes_reason():
    text = '# Falso positivo en domicilio\nSecRuleRemoveById 932380\n'
    item = parser.parse_config(text).exclusions[0]
    assert item.comment == "Falso positivo en domicilio"
    assert item.comment_start == 0


def test_tamiz_own_comment_is_cleaned():
    text = '# Tamiz #12: Upload form\n# Ref: OPS-1\nSecRuleRemoveById 1\n'
    assert parser.parse_config(text).exclusions[0].comment == "Upload form"


def test_broken_chain_is_reported():
    res = parser.parse_config('SecRule ARGS "@rx a" "id:1,phase:2,pass,chain"\n')
    assert res.errors and res.errors[0]["code"] == "broken_chain"


# --------------------------------------------------------------- renderer --

@pytest.mark.parametrize("style", ["crs", "compact"])
def test_render_roundtrip_all_shapes(style):
    shapes = [
        Exclusion(scope="conditional", action="remove_rule", selector_type="tag",
                  selectors=["attack-sqli"], rule_id=10003,
                  conditions=[cond("REQUEST_FILENAME", "endsWith", "/admin-ajax.php")]),
        Exclusion(scope="conditional", action="engine_mode", selector_type=None,
                  engine_mode="DetectionOnly", rule_id=10004,
                  conditions=[cond("REMOTE_ADDR", "ipMatch", "10.0.0.0/8,192.168.1.10")]),
        Exclusion(scope="conditional", action="remove_target", selector_type="tag",
                  selectors=["OWASP_CRS"], variables=["ARGS:/^json\\./"], rule_id=10005,
                  conditions=[cond("REQUEST_URI", "rx", '^/api/(a|b)"q')]),
    ]
    for ex in shapes:
        back = roundtrip(ex, style)
        for f in ("action", "selector_type", "selectors", "variables", "engine_mode", "rule_id"):
            assert getattr(back, f) == getattr(ex, f), f
        assert [(c.variable, c.operator, c.value, c.negate) for c in back.conditions] == \
               [(c.variable, c.operator, c.value, c.negate) for c in ex.conditions]


def test_phase_is_chosen_from_variables():
    ex = Exclusion(scope="conditional", conditions=[cond("REQUEST_FILENAME", "streq", "/a")])
    assert ex.effective_phase() == 1
    ex.conditions.append(cond("ARGS:mode", "streq", "x"))
    assert ex.effective_phase() == 2


def test_render_is_deterministic_and_has_no_timestamps():
    ex = Exclusion(id=3, scope="global", action="remove_rule", selector_type="id",
                   selectors=["920350"], reason="Health checks by IP")
    group = {"slug": "intranet", "name": "Intranet", "id_ranges": "10000-10999"}
    a = render.render_file(group, "after", [ex])
    b = render.render_file(group, "after", [ex])
    assert a == b and a.endswith("\n")
    assert "# Tamiz #3: Health checks by IP" in a


def test_verbatim_source_is_rendered_unchanged():
    src = 'SecRule REQUEST_URI "@beginsWith /x" "id:9, phase:1, pass, nolog, ctl:ruleRemoveById=1"'
    ex = Exclusion(scope="conditional", verbatim=True, source_text=src)
    assert render.render_directives(ex) == src


# ------------------------------------------------------------- validation --

def test_validation_rejects_dangerous_input():
    ex = Exclusion(scope="conditional", action="remove_target", selector_type="id",
                   selectors=["942100"], variables=["ARGS:a,b"], rule_id=1,
                   conditions=[cond("REQUEST_URI", "beginsWith", 'x\\')])
    codes = {(i.field, i.code) for i in validate(ex)}
    assert ("variables", "invalid_variable") in codes
    assert ("conditions.0.value", "trailing_backslash") in codes


def test_validation_phase1_with_body_variable():
    ex = Exclusion(scope="conditional", action="remove_rule", selector_type="id",
                   selectors=["1"], phase=1, conditions=[cond("ARGS:x", "streq", "y")])
    assert any(i.code == "phase1_needs_headers_only" for i in validate(ex))


# ----------------------------------------------------------------- blocks --

def test_blocks_replace_append_remove_and_preserve_foreign_text():
    original = ("# Local rules written by hand\n"
                "SecRule REMOTE_ADDR \"@ipMatch 1.1.1.1\" \"id:1,phase:1,deny\"\n")
    g1 = "# ---- tamiz:begin group=a ----\nX\n# ---- tamiz:end group=a ----"
    g2 = "# ---- tamiz:begin group=b ----\nY\n# ---- tamiz:end group=b ----"
    t1 = blocks.apply_blocks(original, [("a", g1), ("b", g2)])
    assert t1.startswith(original.rstrip("\n"))
    assert set(blocks.find_blocks(t1)) == {"a", "b"}
    t2 = blocks.apply_blocks(t1, [("a", g1.replace("X", "Z")), ("b", None)])
    assert "Z" in t2 and "Y" not in t2 and set(blocks.find_blocks(t2)) == {"a"}
    t3 = blocks.apply_blocks(t2, [("a", None)])
    assert t3 == original


def test_damaged_markers_are_refused():
    bad = "# ---- tamiz:begin group=a ----\nX\n"
    with pytest.raises(blocks.BlockError) as e:
        blocks.find_blocks(bad)
    assert e.value.code == "unterminated_block"
