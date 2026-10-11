"""Core parser for PAC (Proxy Auto-Configuration) file text.

PAC files are JavaScript source that define a top-level function named
``FindProxyForURL(url, host)``. This module extracts that function's full
source text and the names of helper DNS functions it calls, so that an
operator can inspect what the PAC file actually does without executing
JavaScript or having network access.

The implementation is deliberately lexical rather than syntactic: it walks
the text character by character tracking string, line-comment, block-comment,
and brace depth. A full JavaScript parser would be a much larger dependency
and would violate the zero-dependency requirement. The trade-off is that the
extracted function text is the raw slice from the file (whitespace preserved
exactly as written) and helper detection is limited to bareword calls of the
standard PAC DNS helpers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


class PacParseError(ValueError):
    """Raised when the PAC text does not contain a recognisable FindProxyForURL."""


# Standard PAC DNS helper functions defined by the original Netscape spec.
# We only list ones that take a hostname argument; side-effect-free utility
# helpers like ``isPlainHostName`` are left out because they are not DNS.
_DNS_HELPERS = (
    "dnsResolve",
    "isResolvable",
    "isInNet",
    "dnsDomainIs",
    "localHostOrDomainIs",
)


@dataclass
class PacFile:
    """Parsed representation of a PAC file.

    Attributes:
        find_proxy_for_url: Raw source text of the ``FindProxyForURL`` function,
            starting at ``function`` and ending at the matching closing brace.
            ``None`` if no such function was found.
        dns_helpers: Alphabetically sorted list of standard PAC DNS helper
            names that are called as bare words inside ``FindProxyForURL``.
            Only functions that were actually called are listed.
        source: The original PAC file text (unchanged).
    """

    find_proxy_for_url: str | None
    dns_helpers: list[str] = field(default_factory=list)
    source: str = ""


def _find_function(text: str, name: str) -> tuple[int, int] | None:
    """Return [start, end) indices of the top-level ``function NAME`` block.

    "Top-level" means brace depth zero at the ``function`` keyword, so that a
    helper defined inside another function is not mistaken for the target.
    The scan honours string literals and both comment styles so that braces
    inside strings or comments do not affect nesting.
    """
    i = 0
    n = len(text)
    depth = 0
    # Track what we are currently inside so comment/strings cannot move depth.
    while i < n:
        ch = text[i]

        # Line comment: consume to end of line.
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue

        # Block comment: consume to closing */.
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                i += 1
            i += 2
            continue

        # Single-quoted string literal.
        if ch == "'":
            i += 1
            while i < n and text[i] != "'":
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            i += 1
            continue

        # Double-quoted string literal.
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            i += 1
            continue

        if ch == "{":
            depth += 1
            i += 1
            continue

        if ch == "}":
            depth -= 1
            i += 1
            continue

        # Look for ``function NAME`` only when not nested inside a body.
        if depth == 0 and text.startswith("function", i):
            ws = i + len("function")
            if ws < n and text[ws] in " \t\r\n":
                # Skip whitespace between ``function`` and the name.
                j = ws + 1
                while j < n and text[j] in " \t\r\n":
                    j += 1
                if text.startswith(name, j) and (
                    j + len(name) == n
                    or not (text[j + len(name)].isalnum() or text[j + len(name)] == "_")
                ):
                    # Skip past the name and any whitespace until '{'.
                    k = j + len(name)
                    while k < n and text[k] != "{":
                        k += 1
                    if k >= n:
                        return None
                    # k points at '{'. Scan to its matching '}'.
                    d = 0
                    p = k
                    while p < n:
                        c = text[p]
                        if c == "/" and p + 1 < n and text[p + 1] == "/":
                            p += 2
                            while p < n and text[p] not in "\r\n":
                                p += 1
                            continue
                        if c == "/" and p + 1 < n and text[p + 1] == "*":
                            p += 2
                            while p < n and not (
                                text[p] == "*" and p + 1 < n and text[p + 1] == "/"
                            ):
                                p += 1
                            p += 2
                            continue
                        if c == "'":
                            p += 1
                            while p < n and text[p] != "'":
                                if text[p] == "\\" and p + 1 < n:
                                    p += 2
                                    continue
                                p += 1
                            p += 1
                            continue
                        if c == '"':
                            p += 1
                            while p < n and text[p] != '"':
                                if text[p] == "\\" and p + 1 < n:
                                    p += 2
                                    continue
                                p += 1
                            p += 1
                            continue
                        if c == "{":
                            d += 1
                        elif c == "}":
                            d -= 1
                            if d == 0:
                                return i, p + 1
                        p += 1
                    return None
            i += len("function")
            continue

        i += 1

    return None


def _extract_dns_helpers(fn_source: str) -> list[str]:
    """Return the sorted list of standard PAC DNS helper names called in ``fn_source``.

    A "call" is a bareword immediately followed by ``(`` (optional whitespace
    between). This intentionally avoids matching dotted member access like
    ``foo.dnsResolve`` or string occurrences like ``"dnsResolve"``.
    """
    found: set[str] = set()
    i = 0
    n = len(fn_source)
    while i < n:
        c = fn_source[i]
        # Skip strings so names inside them do not count as calls.
        if c == "'" or c == '"':
            quote = c
            i += 1
            while i < n and fn_source[i] != quote:
                if fn_source[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            i += 1
            continue
        # Skip comments.
        if c == "/" and i + 1 < n and fn_source[i + 1] == "/":
            i += 2
            while i < n and fn_source[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and fn_source[i + 1] == "*":
            i += 2
            while i < n and not (
                fn_source[i] == "*" and i + 1 < n and fn_source[i + 1] == "/"
            ):
                i += 1
            i += 2
            continue
        # Try to read an identifier.
        if c.isalpha() or c == "_" or c == "$":
            j = i + 1
            while j < n and (fn_source[j].isalnum() or fn_source[j] in "_$"):
                j += 1
            word = fn_source[i:j]
            # Skip whitespace between identifier and possible '('.
            k = j
            while k < n and fn_source[k] in " \t\r\n":
                k += 1
            if (
                k < n
                and fn_source[k] == "("
                and word in _DNS_HELPERS
                and (i == 0 or fn_source[i - 1] != ".")
            ):
                found.add(word)
            i = j
            continue
        i += 1
    return sorted(found)


def parse_pac(text: str) -> PacFile:
    """Parse PAC file ``text`` and return a :class:`PacFile`.

    If ``FindProxyForURL`` cannot be located, raise :class:`PacParseError`.
    The returned ``find_proxy_for_url`` is the exact substring of ``text`` from
    the ``function`` keyword to the matching closing brace.
    """
    if not isinstance(text, str):
        raise TypeError("parse_pac expects a str")
    span = _find_function(text, "FindProxyForURL")
    if span is None:
        raise PacParseError("no FindProxyForURL function found in PAC text")
    start, end = span
    fn_src = text[start:end]
    return PacFile(
        find_proxy_for_url=fn_src,
        dns_helpers=_extract_dns_helpers(fn_src),
        source=text,
    )
