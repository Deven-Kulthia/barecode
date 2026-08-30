"""Which installed packages the standard library could replace.

This is a curated table, not a guess. Every entry names the specific stdlib
module that does the job and, crucially, how *completely* it does it:

    DROP_IN   the stdlib does the whole job for typical use
    PARTIAL   covers the common path; real gaps are named in `note`
    NONE      no stdlib equivalent exists -- listed so the answer is honest
              rather than silently omitted

The NONE rows matter as much as the others. A tool that claims everything is
replaceable would be lying, and "where the stdlib stops" is the more useful
half of the advice.

Sources for the mappings: the Python standard library documentation, and the
package→stdlib swaps published on the Zero Dependency Hackathon cheat sheet.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .env import Environment, normalise


class Confidence(StrEnum):
    DROP_IN = "drop-in"
    PARTIAL = "partial"
    NONE = "none"


@dataclass(slots=True, frozen=True)
class Swap:
    package: str
    stdlib: str
    confidence: Confidence
    note: str = ""


_D, _P, _N = Confidence.DROP_IN, Confidence.PARTIAL, Confidence.NONE

TABLE: tuple[Swap, ...] = (
    # ── HTTP ────────────────────────────────────────────────────────────────
    Swap("requests", "urllib.request", _P, "no connection pooling, no HTTP/2; fine for scripts and CLIs"),
    Swap("httpx", "urllib.request", _P, "stdlib has no async HTTP client at all"),
    Swap("urllib3", "urllib.request", _P, "urllib3 is what requests uses underneath; stdlib is the layer below that"),
    Swap("aiohttp", "urllib.request", _N, "no async HTTP client in the stdlib; threads + urllib is the workaround"),
    # ── CLI / terminal ──────────────────────────────────────────────────────
    Swap("click", "argparse", _D, "argparse has subparsers, type coercion, and coloured help in 3.14"),
    Swap("typer", "argparse", _P, "you lose type-hint-driven wiring; the parser itself is equivalent"),
    Swap("docopt", "argparse", _D, ""),
    Swap("colorama", "raw ANSI escapes", _D, "cross-platform matters less now that Windows 10+ handles SGR"),
    Swap("termcolor", "raw ANSI escapes", _D, ""),
    Swap("rich", "raw ANSI escapes", _P, "tables and progress are ~50 lines; rich's layout engine is not"),
    Swap("tqdm", "sys.stderr + carriage return", _P, "a progress bar is a \\r and a percentage"),
    Swap("tabulate", "str.format / f-strings", _D, "column alignment is max() over widths"),
    # ── config / serialisation ──────────────────────────────────────────────
    Swap("toml", "tomllib", _P, "tomllib is read-only by design; there is no stdlib TOML writer"),
    Swap("tomli", "tomllib", _D, "tomli was vendored into the stdlib as tomllib in 3.11"),
    Swap("pyyaml", "no equivalent", _N, "no YAML in the stdlib. Use JSON or TOML, or write a subset parser"),
    Swap("python-dotenv", "os.environ + a ~10-line parser", _D, ""),
    Swap("ujson", "json", _D, "stdlib json is C-accelerated; the gap is smaller than it looks"),
    Swap("orjson", "json", _P, "orjson is genuinely faster; stdlib is correct and sufficient for most loads"),
    Swap("jsonschema", "no equivalent", _N, "no schema validation in the stdlib"),
    Swap("pydantic", "dataclasses", _P, "dataclasses give you structure, not runtime validation or coercion"),
    Swap("attrs", "dataclasses", _D, "dataclasses are the stdlib descendant of attrs"),
    Swap("marshmallow", "dataclasses + json", _P, ""),
    # ── testing ─────────────────────────────────────────────────────────────
    Swap("pytest", "unittest", _P, "you lose fixtures and plugins; assertions and discovery are built in"),
    Swap("mock", "unittest.mock", _D, "mock became unittest.mock in 3.3"),
    Swap("freezegun", "unittest.mock.patch", _P, "patch the clock you actually call"),
    Swap("coverage", "sys.monitoring", _P, "3.12+ exposes low-overhead coverage hooks; coverage.py is still richer"),
    # ── crypto / secrets ────────────────────────────────────────────────────
    Swap("passlib", "hashlib.scrypt / hashlib.pbkdf2_hmac", _P, "no Argon2 in the stdlib; scrypt is the defensible choice"),
    Swap("bcrypt", "hashlib.scrypt", _P, "different algorithm, comparable purpose; document the choice"),
    Swap("pyotp", "hmac + struct + base64", _D, "TOTP is about 15 lines over stdlib primitives"),
    Swap("pyjwt", "hmac + base64 + json", _P, "HS256 is straightforward; RS256 needs asymmetric key handling"),
    Swap("cryptography", "hashlib / hmac / secrets", _N, "no AES or asymmetric ciphers in the stdlib. Never roll your own"),
    Swap("secrets", "secrets", _D, "this is the stdlib module; a same-named package is a typosquat risk"),
    # ── dates / time ────────────────────────────────────────────────────────
    Swap("pytz", "zoneinfo", _D, "zoneinfo (3.9) reads the system tz database"),
    Swap("python-dateutil", "datetime.fromisoformat", _P, "3.11 parses most ISO 8601; arbitrary human formats it does not"),
    Swap("arrow", "datetime + zoneinfo", _P, ""),
    # ── compression / archives ──────────────────────────────────────────────
    Swap("zstandard", "compression.zstd", _D, "new in 3.14, wired into tarfile and zipfile"),
    Swap("brotli", "no equivalent", _N, "gzip, bz2, lzma and zstd are in; brotli is not"),
    # ── concurrency / caching / files ───────────────────────────────────────
    Swap("cachetools", "functools.lru_cache", _P, "lru_cache has no TTL; a TTL cache is ~20 lines"),
    Swap("filelock", "fcntl.flock / os.O_EXCL", _P, "portable locking needs a Windows branch"),
    Swap("watchdog", "polling with os.stat", _P, "no filesystem-event API in the stdlib; polling is the honest fallback"),
    Swap("tenacity", "a loop with time.sleep", _P, "exponential backoff is four lines"),
    Swap("joblib", "concurrent.futures", _P, ""),
    # ── legacy / no longer needed ───────────────────────────────────────────
    Swap("six", "nothing", _D, "Python 2 compatibility shim; delete it"),
    Swap("pathlib2", "pathlib", _D, "backport of a stdlib module since 3.4"),
    Swap("enum34", "enum", _D, "backport of a stdlib module since 3.4"),
    Swap("dataclasses", "dataclasses", _D, "backport of a stdlib module since 3.7"),
    Swap("typing-extensions", "typing", _P, "only needed for types newer than your interpreter"),
    Swap("importlib-metadata", "importlib.metadata", _D, "backport of a stdlib module since 3.8"),
    Swap("chardet", "bytes.decode with errors=", _P, "charset detection is genuinely hard; often you know the encoding"),
    # ── numerics (honest NONEs) ─────────────────────────────────────────────
    Swap("numpy", "array / statistics / math", _N, "no vectorised numerics in the stdlib. Keep numpy"),
    Swap("pandas", "csv + sqlite3 + statistics", _N, "no dataframes in the stdlib. Keep pandas"),
)

BY_NAME = {normalise(s.package): s for s in TABLE}


@dataclass(slots=True, frozen=True)
class Hit:
    swap: Swap
    version: str
    direct: bool  # True when nothing else in the environment requires it


def killable(env: Environment, reverse: dict[str, list[str]] | None = None) -> list[Hit]:
    """Installed packages that appear in the substitution table.

    `reverse` (from graph.build) lets us mark which hits are things the user
    installed themselves versus transitive dependencies they cannot simply
    remove. Removing a direct dependency is a decision; removing a transitive
    one is not available to you.
    """
    hits = []
    for name, pkg in env.packages.items():
        swap = BY_NAME.get(name)
        if swap is None:
            continue
        direct = not (reverse or {}).get(name)
        hits.append(Hit(swap=swap, version=pkg.version, direct=direct))
    hits.sort(key=lambda h: (h.swap.confidence != Confidence.DROP_IN, not h.direct, h.swap.package))
    return hits
