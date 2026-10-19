"""Lightweight lexical helpers that make regex rules more precise without a full parser.

* `mask_comments` blanks out comments (keeping string literals) so a commented-out call is not a finding.
  Output has exactly the same length and line breaks as the input, so offsets and line numbers still match.
* `BlockIndex` tells which `{ ... }` headers enclose an offset, so a rule can skip, for example,
  `isMinifyEnabled = false` inside `debug { }` or a call guarded by `if (BuildConfig.DEBUG) { }`.

This is deliberately approximate (no Kotlin templates or macros). When it is unsure it leaves the text
alone, which keeps the rules conservative rather than silently dropping findings.
"""

from __future__ import annotations

import re
from bisect import bisect_right

CODE_SUFFIXES = {".kt", ".java", ".kts", ".gradle"}
XML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
DEBUG_RANGE_CHARS = 200  # how much text before a "{" counts as its header


def _blank(text: str) -> str:
    """Replace everything except line breaks with spaces, preserving length and lines."""
    return "".join(ch if ch in "\r\n" else " " for ch in text)


def mask_comments(source: str, suffix: str) -> str:
    """Return `source` with comments blanked out; string literals are kept as they are."""
    if suffix == ".xml":
        return XML_COMMENT.sub(lambda match: _blank(match.group(0)), source)
    if suffix not in CODE_SUFFIXES:
        return source

    out: list[str] = []
    i, n = 0, len(source)
    while i < n:
        two = source[i:i + 2]
        if source.startswith('"""', i):  # Kotlin raw string / Java text block
            end = source.find('"""', i + 3)
            end = n if end == -1 else end + 3
            out.append(source[i:end])
            i = end
        elif source[i] in "\"'":
            quote = source[i]
            j = i + 1
            while j < n and source[j] != "\n":
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == quote:
                    j += 1
                    break
                j += 1
            j = min(j, n)
            out.append(source[i:j])
            i = j
        elif two == "//":
            end = source.find("\n", i)
            end = n if end == -1 else end
            out.append(_blank(source[i:end]))
            i = end
        elif two == "/*":
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append(_blank(source[i:end]))
            i = end
        else:
            out.append(source[i])
            i += 1
    return "".join(out)


class BlockIndex:
    """Finds the headers of the `{ }` blocks that enclose an offset (innermost last)."""

    def __init__(self, masked_source: str) -> None:
        self._blocks: list[tuple[int, int, str]] = []  # (start, end, header)
        stack: list[tuple[int, str]] = []
        in_string: str | None = None
        last_boundary = -1  # offset of the latest newline, ";", "{" or "}": where a block header begins
        for index, ch in enumerate(masked_source):
            if ch == "\n":
                in_string = None
                last_boundary = index
                continue
            if in_string:
                if ch == in_string:
                    in_string = None
                continue
            if ch in "\"'":
                in_string = ch
            elif ch == "{":
                header_start = max(last_boundary, index - DEBUG_RANGE_CHARS)
                stack.append((index, masked_source[header_start + 1:index].strip()))
                last_boundary = index
            elif ch == "}":
                if stack:
                    start, header = stack.pop()
                    self._blocks.append((start, index, header))
                last_boundary = index
            elif ch == ";":
                last_boundary = index
        self._blocks.extend((start, len(masked_source), header) for start, header in stack)  # unclosed blocks
        self._blocks.sort()
        self._starts = [block[0] for block in self._blocks]

    def headers_at(self, offset: int) -> list[str]:
        upto = bisect_right(self._starts, offset)
        return [header for start, end, header in self._blocks[:upto] if start < offset <= end]
