"""Terminal styling and width-aware output.

Normally: ``colorama`` / ``rich`` / ``termcolor``.
Instead:   raw ANSI SGR escapes plus ``os.isatty``.

The rules for whether colour is emitted, in priority order:

1. ``--no-color`` on the command line, or ``NO_COLOR`` set to anything at all
   (the no-color.org convention -- presence matters, value does not).
2. ``FORCE_COLOR`` set, or ``TERM`` is not ``dumb`` and the stream is a TTY.
3. Otherwise, plain text.

Track A's official guidance is explicit about this: "Honour NO_COLOR and check
whether stdout is a TTY." Piping our output into a file or another program must
produce clean, unstyled text.
"""

from __future__ import annotations

import os
import sys
from typing import IO

# SGR codes. Deliberately a small, boring set -- we need eight, not a library.
_CODES = {
    "reset": 0,
    "bold": 1,
    "dim": 2,
    "italic": 3,
    "underline": 4,
    "red": 31,
    "green": 32,
    "yellow": 33,
    "blue": 34,
    "magenta": 35,
    "cyan": 36,
    "grey": 90,
}


class Style:
    """Emits ANSI escapes, or nothing at all when colour is disabled.

    One instance is created per run and threaded through the renderers, so the
    colour decision is made exactly once, in one place, from one set of inputs.
    """

    __slots__ = ("enabled",)

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    @classmethod
    def detect(cls, stream: IO[str] | None = None, *, force_off: bool = False) -> "Style":
        stream = stream if stream is not None else sys.stdout
        if force_off or "NO_COLOR" in os.environ:
            return cls(False)
        if "FORCE_COLOR" in os.environ:
            return cls(True)
        if os.environ.get("TERM") == "dumb":
            return cls(False)
        try:
            tty = stream.isatty()
        except (AttributeError, ValueError):
            tty = False
        return cls(tty)

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        codes = ";".join(str(_CODES[s]) for s in styles)
        return f"\x1b[{codes}m{text}\x1b[0m"

    # Named helpers keep call sites readable at a glance.
    def ok(self, text: str) -> str:
        return self(text, "green")

    def warn(self, text: str) -> str:
        return self(text, "yellow")

    def bad(self, text: str) -> str:
        return self(text, "red", "bold")

    def head(self, text: str) -> str:
        return self(text, "bold")

    def faint(self, text: str) -> str:
        return self(text, "grey")


def plain_len(text: str) -> int:
    """Visible width of `text`, ignoring any ANSI escape sequences.

    Normally: ``wcwidth`` / ``rich.cells``.
    Instead:  a tiny state machine. We only need to align columns in tables, so
    full Unicode east-asian width handling would be complexity we never use.
    """
    width = 0
    in_escape = False
    for ch in text:
        if in_escape:
            if ch.isalpha():
                in_escape = False
        elif ch == "\x1b":
            in_escape = True
        else:
            width += 1
    return width
