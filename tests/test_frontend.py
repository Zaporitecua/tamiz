"""Static checks of the browser code: there is no build step to catch these.

* every static ``import { a, b } from "./x.js"`` points to a file that
  exports ``a`` and ``b`` (a typo here only shows up as a blank page);
* index.html only references files that exist and has no inline script or
  style, and no template sets ``style=`` or ``on...=`` attributes: the
  Content-Security-Policy blocks all of them without any visible error;
* every view the router can load exists and exports ``render``.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "tamiz/static"
JS = STATIC / "js"

IMPORT_RE = re.compile(r'^import\s*\{([^}]*)\}\s*from\s*"([^"]+)";', re.M)
EXPORT_RE = re.compile(r"^export\s+(?:async\s+)?(?:function\*?|const|let|class)\s+([A-Za-z_$][\w$]*)", re.M)
EXPORT_LIST_RE = re.compile(r"^export\s*\{([^}]*)\}", re.M)
ROUTE_RE = re.compile(r'^\s*\[/.*/, "([a-z-]+)"\],?\s*$', re.M)


def js_files() -> list[Path]:
    return sorted(JS.rglob("*.js"))


def names(group: str) -> set[str]:
    return {n.strip().split(" as ")[0].strip() for n in group.split(",") if n.strip()}


def exports(path: Path) -> set[str]:
    text = path.read_text()
    found = set(EXPORT_RE.findall(text))
    for group in EXPORT_LIST_RE.findall(text):
        found |= {n.strip().split(" as ")[-1].strip() for n in group.split(",") if n.strip()}
    return found


@pytest.mark.parametrize("path", js_files(), ids=lambda p: str(p.relative_to(JS)))
def test_static_imports_resolve(path):
    for imported, target in IMPORT_RE.findall(path.read_text()):
        dep = (path.parent / target).resolve()
        assert dep.exists(), f"{path.name}: {target} not found"
        missing = names(imported) - exports(dep)
        assert not missing, f"{path.name}: {target} does not export {sorted(missing)}"


def test_no_inline_styles_or_handlers():
    for f in js_files() + [STATIC / "index.html"]:
        text = f.read_text()
        assert not re.search(r"\sstyle=", text), f"{f.name}: style= attribute (blocked by the CSP)"
        assert not re.search(r"\son[a-z]+=", text), f"{f.name}: inline event handler (blocked by the CSP)"


def test_index_references_exist():
    index = (STATIC / "index.html").read_text()
    refs = re.findall(r'(?:src|href)="static/([^"]+)"', index)
    assert refs
    assert [r for r in refs if not (STATIC / r).exists()] == []
    assert not re.search(r"<script(?![^>]*\bsrc=)", index), "inline <script> (blocked by the CSP)"
    assert "<style" not in index


def test_router_views_exist():
    views = set(ROUTE_RE.findall((JS / "app.js").read_text())) | {"login"}
    assert len(views) > 10
    for name in sorted(views):
        view = JS / "views" / f"{name}.js"
        assert view.exists(), f"views/{name}.js missing"
        assert "render" in exports(view), f"views/{name}.js does not export render"


def test_sudoers_tail_rule_is_anchored():
    """In sudoers a * in the arguments also matches spaces: "tail -c * -- log"
    would allow "tail -c 1 /etc/shadow -- log". The suggested rule must use an
    anchored regular expression that only accepts a byte count."""
    src = (JS / "views/target-form.js").read_text(encoding="utf-8")
    assert "cmds.push(`tail -c * --" not in src
    assert "tail ^-c [0-9]+ -- " in src
    for doc in ("README.md", "README.es.md", "examples/sudoers-tamiz"):
        text = (STATIC.parents[1] / doc).read_text(encoding="utf-8")
        rules = [ln for ln in text.splitlines() if "/usr/bin/tail " in ln and not ln.lstrip().startswith("#")]
        assert rules and all("tail ^-c [0-9]+ -- " in ln for ln in rules), doc
