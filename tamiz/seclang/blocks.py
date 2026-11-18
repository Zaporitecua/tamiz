"""Managed blocks inside files Tamiz does not own.

Some setups only load exclusions from a file that also holds other content,
for example ``REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`` mounted into the
official CRS container image. In that case Tamiz owns only the text between
its markers, one block per group::

    # ---- tamiz:begin group=intranet ----
    ...
    # ---- tamiz:end group=intranet ----

Everything outside the markers is preserved byte for byte. If the markers are
damaged (missing end, nested, duplicated) Tamiz refuses to touch the file
rather than guess.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .lexer import split_lines

BEGIN_RE = re.compile(r"^# -{2,} tamiz:begin group=([a-z0-9][a-z0-9-]*) -{2,}\s*$")
END_RE = re.compile(r"^# -{2,} tamiz:end group=([a-z0-9][a-z0-9-]*) -{2,}\s*$")


class BlockError(ValueError):
    def __init__(self, code: str, line: int, slug: str = ""):
        super().__init__(f"{code} at line {line + 1} ({slug})")
        self.code = code
        self.line = line
        self.slug = slug


@dataclass
class Block:
    slug: str
    start: int   # line of the begin marker
    end: int     # line of the end marker
    text: str


def find_blocks(text: str) -> dict[str, Block]:
    lines = split_lines(text)
    blocks: dict[str, Block] = {}
    open_slug: str | None = None
    open_line = 0
    for i, line in enumerate(lines):
        mb = BEGIN_RE.match(line)
        me = END_RE.match(line)
        if mb:
            if open_slug is not None:
                raise BlockError("nested_block", i, mb.group(1))
            if mb.group(1) in blocks:
                raise BlockError("duplicated_block", i, mb.group(1))
            open_slug, open_line = mb.group(1), i
        elif me:
            if open_slug is None:
                raise BlockError("end_without_begin", i, me.group(1))
            if me.group(1) != open_slug:
                raise BlockError("mismatched_end", i, me.group(1))
            blocks[open_slug] = Block(open_slug, open_line, i, "\n".join(lines[open_line:i + 1]))
            open_slug = None
        elif "tamiz:begin" in line or "tamiz:end" in line:
            raise BlockError("malformed_marker", i)
    if open_slug is not None:
        raise BlockError("unterminated_block", open_line, open_slug)
    return blocks


def apply_blocks(text: str, changes: list[tuple[str, str | None]]) -> str:
    """Return ``text`` with blocks replaced, removed (``None``) or appended.

    ``changes`` is an ordered list of ``(slug, new_block_text)``. New blocks are
    appended at the end of the file in the order given.
    """
    existing = find_blocks(text)
    lines = split_lines(text)
    replace: dict[int, tuple[int, list[str]]] = {}
    append: list[str] = []
    for slug, content in changes:
        block = existing.get(slug)
        new_lines = split_lines(content) if content is not None else []
        if block is None:
            if content is not None:
                append.append(content)
            continue
        start, end = block.start, block.end
        if content is None:
            # Take one separating blank line with the removed block, so that
            # adding and later removing a block leaves the file as it was.
            if end + 1 < len(lines) and lines[end + 1].strip() == "":
                end += 1
            elif start > 0 and lines[start - 1].strip() == "":
                start -= 1
        replace[start] = (end, new_lines)

    out: list[str] = []
    i = 0
    while i < len(lines):
        if i in replace:
            end, new_lines = replace[i]
            out.extend(new_lines)
            i = end + 1
            continue
        out.append(lines[i])
        i += 1
    for content in append:
        while out and out[-1].strip() == "":
            out.pop()
        if out:
            out.append("")
        out.extend(split_lines(content))
    return ("\n".join(out) + "\n") if out else ""


def strip_blocks(text: str) -> str:
    """Text outside every Tamiz block (used to detect foreign content)."""
    blocks = find_blocks(text)
    lines = split_lines(text)
    skip = set()
    for b in blocks.values():
        skip.update(range(b.start, b.end + 1))
    return "\n".join(line for i, line in enumerate(lines) if i not in skip)
