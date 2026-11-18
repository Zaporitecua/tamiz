"""Every text the UI or the API can show exists in Spanish and English."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "tamiz"
I18N = (ROOT / "static/js/i18n.js").read_text()


def keys(section: str) -> set[str]:
    return set(re.findall(r'"([a-z_]+\.[A-Za-z0-9_]*)":', section))


ES = keys(I18N[I18N.index("const es = {"):I18N.index("const en = {")])
EN = keys(I18N[I18N.index("const en = {"):I18N.index("const DICTS")])


def py_codes(pattern: str) -> set[str]:
    found: set[str] = set()
    for f in ROOT.rglob("*.py"):
        found.update(re.findall(pattern, f.read_text()))
    return found


def test_same_keys_in_both_languages():
    assert ES - EN == set(), sorted(ES - EN)
    assert EN - ES == set(), sorted(EN - ES)


def test_every_static_key_used_by_the_ui_exists():
    used = set()
    for f in (ROOT / "static/js").rglob("*.js"):
        used.update(re.findall(r'\bt\("([a-z_]+\.[A-Za-z0-9_]+)"', f.read_text()))
    missing = sorted(k for k in used if k not in ES and not k.endswith("_"))  # "x_" + var
    assert not missing, missing


def test_api_error_codes_are_translated():
    codes = py_codes(r'ApiError\(\d+, "([a-z_0-9]+)"')
    codes |= py_codes(r'TransportError\("([a-z_0-9]+)"')
    codes |= py_codes(r'DeployError\("([a-z_0-9]+)"')
    codes |= py_codes(r'Conflict\("([a-z_0-9]+)"')
    codes -= {"file_"}  # composed with the file status at runtime
    missing = sorted(c for c in codes if f"err.{c}" not in ES)
    assert not missing, missing


def test_issue_codes_are_translated():
    codes = py_codes(r'err\("[a-z_.0-9]+", "([a-z_0-9]+)"')
    codes |= py_codes(r'add\("([a-z_0-9]+)", "(?:error|warning|info)"')
    codes |= py_codes(r'Issue\([^)]*?"([a-z_0-9]+)", "(?:error|warning|info)"')
    codes |= {c for c in py_codes(r'"code": "([a-z_0-9]+)"')
              if c not in {"lex_error", "broken_chain", "comment_with_continuation", "path_collision",
                           "unknown_block", "crs_not_found", "discover_failed", "no_rules_file_found",
                           "export_target", "no_entry_files", "include_cycle", "too_many_files", "unreadable"}}
    missing = sorted(c for c in codes if f"issue.{c}" not in ES)
    assert not missing, missing


def test_history_actions_and_steps_are_translated():
    actions = py_codes(r'log_history\(conn, [^,]+, "([a-z_]+)"')
    actions |= {"exclusion_created", "exclusion_updated", "review_approved", "review_rejected",
                "validate", "reload"}
    assert sorted(a for a in actions if f"action.{a}" not in ES) == []
    steps = py_codes(r'Step\("([a-z_]+)"')
    assert sorted(s for s in steps if f"step.{s}" not in ES) == []
