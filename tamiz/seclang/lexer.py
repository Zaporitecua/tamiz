"""Tokenizer for ModSecurity configuration text (SecLang).

The lexer turns configuration text into a flat list of statements and keeps
the exact source of every one of them (line span and original text). Callers
rely on that to reproduce or cut a statement byte for byte: Tamiz never
rewrites configuration it did not generate unless the user explicitly edits
it.

Rules followed here, shared by Apache (mod_security2) and libmodsecurity v3:

* A line whose last non-blank character is a backslash continues on the next
  line. The backslash is dropped and the next line is appended as-is, so the
  indentation of continuation lines becomes whitespace inside the logical
  line. This is how the CRS formats its rules.
* A line starting with ``#`` (after optional whitespace) is a comment. Comments
  are single physical lines.
* Arguments are separated by whitespace and may be wrapped in double or single
  quotes. Inside quotes, a backslash before the quote character escapes it;
  every other backslash is kept literally (regexes depend on that).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

CONTINUATION_RE = re.compile(r"\\[ \t]*$")


class LexError(ValueError):
    """Raised when configuration text cannot be tokenized safely."""

    def __init__(self, message: str, line: int):
        super().__init__(f"line {line + 1}: {message}")
        self.line = line
        self.reason = message


@dataclass
class Statement:
    kind: str                 # "directive" | "comment" | "blank"
    start: int                # first physical line, 0-based
    end: int                  # last physical line, inclusive
    text: str                 # exact source lines joined with "\n"
    name: str = ""            # directive name as written
    args: list[str] = field(default_factory=list)
    logical: str = ""         # line after joining continuations

    @property
    def lname(self) -> str:
        return self.name.lower()


def split_lines(text: str) -> list[str]:
    """Split text into physical lines, normalising line endings.

    A trailing newline does not produce an extra empty line.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text.endswith("\n"):
        text = text[:-1]
    if text == "":
        return []
    return text.split("\n")


def join_continuations(parts: list[str]) -> str:
    out = []
    for i, part in enumerate(parts):
        if i < len(parts) - 1:
            out.append(CONTINUATION_RE.sub("", part))
        else:
            out.append(part)
    return "".join(out)


def parse_args(s: str, line: int = 0) -> list[str]:
    """Split the argument part of a directive into unquoted arguments."""
    args: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t":
            i += 1
            continue
        if c in "\"'":
            quote = c
            i += 1
            buf = []
            closed = False
            while i < n:
                ch = s[i]
                if ch == "\\" and i + 1 < n and s[i + 1] == quote:
                    buf.append(quote)
                    i += 2
                    continue
                if ch == quote:
                    closed = True
                    i += 1
                    break
                buf.append(ch)
                i += 1
            if not closed:
                raise LexError("unterminated quoted argument", line)
            args.append("".join(buf))
            continue
        j = i
        while j < n and s[j] not in " \t":
            j += 1
        args.append(s[i:j])
        i = j
    return args


def lex(text: str) -> list[Statement]:
    """Tokenize configuration text into statements."""
    lines = split_lines(text)
    out: list[Statement] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            out.append(Statement("blank", i, i, line))
            i += 1
            continue
        if stripped.startswith("#"):
            out.append(Statement("comment", i, i, line))
            i += 1
            continue
        j = i
        while CONTINUATION_RE.search(lines[j]) and j + 1 < len(lines):
            j += 1
        if CONTINUATION_RE.search(lines[j]) and j == len(lines) - 1:
            raise LexError("line continuation at end of file", j)
        parts = lines[i:j + 1]
        logical = join_continuations(parts).strip()
        m = re.match(r"(\S+)\s*(.*)", logical, re.S)
        name, rest = m.group(1), m.group(2)
        args = parse_args(rest, i)
        out.append(Statement("directive", i, j, "\n".join(parts), name, args, logical))
        i = j + 1
    return out


# ---------------------------------------------------------------- actions ---

@dataclass
class Action:
    name: str          # lower-cased action name ("id", "phase", "ctl", "t" ...)
    value: str | None  # unquoted value, None when the action has no value
    raw: str           # exactly as written (trimmed)


def split_actions(s: str) -> list[str]:
    """Split an action list on commas that are not inside single quotes."""
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if in_quote:
            if c == "\\" and i + 1 < n and s[i + 1] == "'":
                buf.append("\\'")
                i += 2
                continue
            if c == "'":
                in_quote = False
            buf.append(c)
            i += 1
            continue
        if c == "'":
            in_quote = True
            buf.append(c)
        elif c == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    if in_quote:
        raise ValueError("unterminated single quote in action list")
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def parse_actions(s: str) -> list[Action]:
    actions = []
    for raw in split_actions(s):
        name, sep, value = raw.partition(":")
        name = name.strip().lower()
        if not sep:
            actions.append(Action(name, None, raw))
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
            value = value[1:-1].replace("\\'", "'")
        actions.append(Action(name, value, raw))
    return actions
