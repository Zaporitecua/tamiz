"""Text colours in tokens.css keep WCAG AA contrast (4.5:1) in both themes.

Dark is the default theme (``:root``); light is ``:root[data-theme="light"]``.
"""
import re
from pathlib import Path

TOKENS = (Path(__file__).resolve().parents[1] / "tamiz/static/css/tokens.css").read_text()

# Colours used for text, and the backgrounds they appear on.
TEXT = ["ink", "ink-2", "ink-3", "steel-ink", "ok", "pending", "warn", "rust"]
BACKGROUNDS = ["paper", "surface", "sunken"]
ON_TINT = ["ok", "pending", "warn", "rust"]
HEX = r"#[0-9a-fA-F]{6}"


def declarations(block: str) -> dict[str, str]:
    return {k: v.strip() for k, v in re.findall(r"--([a-z0-9-]+):\s*([^;]+);", block)}


def luminance(hex_: str) -> float:
    rgb = [int(hex_[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def ratio(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def themes() -> dict[str, dict[str, str]]:
    body = TOKENS[TOKENS.index("@layer tokens {"):]
    light_at = body.index(':root[data-theme="light"]')
    dark = declarations(body[:light_at])
    light = {**dark, **declarations(body[light_at:])}
    return {"dark": dark, "light": light}


def test_light_theme_redefines_every_colour_of_the_dark_one():
    body = TOKENS[TOKENS.index("@layer tokens {"):]
    light_at = body.index(':root[data-theme="light"]')
    dark_colours = {k for k, v in declarations(body[:light_at]).items() if re.search(HEX, v) or "rgba" in v}
    light_keys = set(declarations(body[light_at:]))
    assert dark_colours - light_keys == set(), sorted(dark_colours - light_keys)


def test_text_colours_meet_aa():
    failures = []
    for name, p in themes().items():
        for fg in TEXT:
            for bg in BACKGROUNDS + ["steel-tint"]:
                r = ratio(p[fg], p[bg])
                if r < 4.5 and not (bg == "steel-tint" and fg not in ("ink", "steel-ink")):
                    failures.append(f"{name}: --{fg} on --{bg} = {r:.2f}")
        for fg in ON_TINT:
            r = ratio(p[fg], p[f"{fg}-tint"])
            if r < 4.5:
                failures.append(f"{name}: --{fg} on --{fg}-tint = {r:.2f}")
        # Primary button: its text against every stop of the metallic sheen.
        for stop in re.findall(HEX, p["steel-sheen"]):
            r = ratio(p["steel-on"], stop)
            if r < 4.5:
                failures.append(f"{name}: --steel-on on sheen stop {stop} = {r:.2f}")
    assert not failures, failures


def test_focus_ring_and_rims_are_visible():
    # Non-text contrast (WCAG 1.4.11): 3:1 against the surfaces they sit on.
    for name, p in themes().items():
        for bg in BACKGROUNDS:
            assert ratio(p["steel"], p[bg]) >= 3, f"{name}: --steel on --{bg}"
