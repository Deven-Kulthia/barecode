# STDLIB.md — what the standard library is doing instead

BareCode has **zero third-party runtime dependencies and zero third-party dev
dependencies.** No `pip install` is needed to build it, run it, or test it.

This file is the receipt. Every row is something we would normally have
installed, the standard library facility we used instead, and — where it
matters — what we gave up by doing so.

Verify the claim yourself, offline, in about a second:

```console
$ make prove
```

That AST-walks every source file, collects every import, and asserts each one is
in `sys.stdlib_module_names` — the frozen set CPython builds at compile time
listing exactly what ships in the box. It also asserts `pyproject.toml` declares
no dependencies. Non-zero exit if either check fails.

Target runtime: **CPython 3.14.4** (works on ≥3.13; see *Version floor* below).

---

## The substitutions

### 1. `click` / `typer` → `argparse`

**Normally:** `click` (or `typer`) for a multi-command CLI with typed flags.
**Instead:** `argparse` with `add_subparsers()`, in `src/barecode/cli.py`.

`argparse` already provides subcommands, `type=` coercion, `choices=`,
`action="count"`, mutually-exclusive groups, auto-generated `--help`, and — new
in 3.14 — **coloured help output** via `ArgumentParser(color=True)`. We use a
shared parent parser (`parents=[common]`) so every subcommand inherits
`--path`, `--json`, `--quiet`, `--no-color` and `--fail-on` without repetition.

**What we gave up:** nothing material for this tool. `click`'s decorator style
is more pleasant to write; the parser behaviour is equivalent.

**Gotcha we hit and documented:** a positional argument on a *parent* parser
binds before the subcommand's own positional, so `barecode why requests /path`
silently assigned `requests` to the path. We made the environment `-p/--path`
instead of a positional — one rule, no ordering ambiguity on any command.

---

### 2. `colorama` / `termcolor` / `rich` → raw ANSI SGR escapes

**Normally:** `colorama` for cross-platform colour, or `rich` for styled output.
**Instead:** a 12-entry SGR code table and one `Style` class,
`src/barecode/ansi.py` (~90 lines).

The colour decision is made **once per run** from an explicit precedence chain,
which is the part libraries usually get right and hand-rolled code usually gets
wrong:

1. `--no-color`, or `NO_COLOR` present in the environment (the
   [no-color.org](https://no-color.org) convention — *presence* matters, value
   is ignored), disables colour.
2. `FORCE_COLOR` enables it.
3. `TERM=dumb` disables it.
4. Otherwise: `stream.isatty()`.

Track A's official guidance asks for exactly this — "Honour NO_COLOR and check
whether stdout is a TTY" — so piping our output to a file or another program
yields clean, unstyled text.

**What we gave up:** `rich`'s layout engine, tables and progress bars. We
needed none of them. Windows support relies on Windows 10+ handling SGR
natively, which `colorama` used to paper over.

---

### 3. `wcwidth` / `rich.cells` → a 20-line escape-skipping width function

**Normally:** `wcwidth` to measure printable width for column alignment.
**Instead:** `plain_len()` in `src/barecode/ansi.py`, a small state machine that
walks the string and skips `ESC ... <letter>` sequences.

**What we gave up:** correct East-Asian wide-character and combining-mark
widths. We only align ASCII package names and versions, so the full Unicode
width tables would be complexity we never execute. **This is a real limitation:**
a CJK package name would misalign by a column. Named rather than hidden.

---

### 4. `packaging` (METADATA parsing) → `email.parser`

**Normally:** `packaging` / `importlib.metadata` to read distribution metadata.
**Instead:** `email.parser.BytesParser`, in `src/barecode/env.py`.

This one is not really a substitution — it's using the *correct* tool. Wheel
`METADATA` files are genuine RFC 822 documents (`Name:`, `Version:`,
`Requires-Dist:` repeated), so the standard library's email parser is the right
reader, not a workaround. `msg.get_all("Requires-Dist")` handles repeated
headers for free.

**What we hit in the real world:** with the default `compat32` policy,
`msg.get()` returns a `Header` **object rather than a `str`** when a header is
RFC 2047-encoded or malformed — and real `METADATA` files in the wild contain
both. Our `_header()` helper coerces with `str()` and collapses whitespace,
because some packages inline an entire licence text into the `License:` field.
There is a regression test for each case.

---

### 5. `packaging.utils.canonicalize_name` → `re.sub`

**Normally:** `packaging` for PEP 503 name normalisation.
**Instead:** one compiled regex, `re.sub(r"[-_.]+", "-", name).lower()`.

That *is* the PEP 503 algorithm in full. `Zope.Interface` and
`zope_interface` both normalise to `zope-interface`, which is what lets us match
a `Requires-Dist` line against an installed distribution reliably.

**What we gave up:** nothing. This is the entire specification.

---

### 6. `packaging.requirements` → a reduced PEP 508 regex

**Normally:** `packaging.requirements.Requirement` for dependency strings.
**Instead:** one verbose regex in `src/barecode/graph.py` capturing name,
extras, version specifier and environment marker.

**What we gave up, deliberately:** we **do not evaluate markers.** Correctly
evaluating `python_version < "3.11" and extra == "dev"` requires the full marker
grammar and an evaluation environment; approximating it would produce dependency
edges that are quietly wrong. Instead we record the marker verbatim and label
the edge conditional. We also do not compare version specifiers — we report
what is installed, not whether it satisfies a range.

That is a smaller feature set than `packaging` and an honest one. Being wrong
about a dependency edge is worse than declining to guess.

---

### 7. `networkx` → `dict` + `collections.deque`

**Normally:** `networkx` for the dependency graph.
**Instead:** two dicts (forward and reverse adjacency) and a BFS, in
`src/barecode/graph.py`.

`why` is breadth-first over the reverse graph, so the first path found per root
is the shortest; a per-path membership check makes dependency cycles (legal in
Python packaging, and they do occur) terminate instead of looping. `blast_radius`
is the same traversal without path tracking.

**What we gave up:** every other graph algorithm. We need reachability and
shortest path. `networkx` would be a large dependency for a dict of lists.

---

### 8. `hashlib` usage: streaming digests via `hashlib.file_digest`

**Normally:** a hand-rolled `while chunk := f.read(65536)` loop, or a helper
from a utility package.
**Instead:** `hashlib.file_digest(fh, "sha256")` (3.11+), in
`src/barecode/integrity.py`.

It streams the file without loading it into memory and releases the GIL while
reading, which is what makes our thread pool actually help.

---

### 9. Wheel hash encoding → `base64.urlsafe_b64encode`

**Normally:** `packaging` or `installer` to decode RECORD hash fields.
**Instead:** `base64.urlsafe_b64encode(digest).rstrip(b"=")`.

That is precisely the encoding PEP 376 / the wheel spec mandate for RECORD:
urlsafe base64 of the raw digest with padding stripped. Three lines.

---

### 10. A CSV reader for `RECORD` → `csv`

**Normally:** `line.split(",")`, which is wrong.
**Instead:** `csv.reader`, in `src/barecode/integrity.py`.

`RECORD` is real CSV: a file whose path contains a comma is **quoted**. A naive
split corrupts those rows and produces false "missing file" findings. There is a
test (`test_quoted_csv_path_with_comma`) that fails if anyone swaps this back.

---

### 11. `tqdm` / thread-pool helpers → `concurrent.futures.ThreadPoolExecutor`

**Normally:** `joblib`, or a manual `threading` + `queue` construction.
**Instead:** `ThreadPoolExecutor(max_workers=...).map(...)`, sized from
`os.process_cpu_count()` rather than a magic constant.

Hashing thousands of files is I/O bound and `file_digest` releases the GIL, so
threads give a real speedup: 4,927 files across 190 packages in **3.4 s**.

---

### 12. `pytest` → `unittest`

**Normally:** `pytest` plus plugins.
**Instead:** `unittest` — 79 tests in `tests/test_barecode.py`, run by
`make test`.

The hackathon permits a dev-only test dependency *for languages that ship no
test framework*. **Python ships `unittest`, so we do not use that exception at
all** and have no dev dependencies either.

Fixtures are synthesised on disk (`Fixture` builds real `.dist-info` trees with
real RECORD hashes in a `TemporaryDirectory`), so the suite is hermetic and
offline — it never calls `pip`. `subTest`-free table-driven loops, `addCleanup`
for teardown, `redirect_stdout`/`redirect_stderr` from `contextlib` to assert on
stream discipline.

**What we gave up:** `pytest`'s fixture injection and assertion rewriting.
`assertEqual` is less pretty than bare `assert`; the tests are no less strict.

---

### 13. `pyinstaller` / `shiv` / `pex` → `zipapp`

**Normally:** a packaging tool to produce a single runnable file.
**Instead:** `python -m zipapp` in the `Makefile`, producing a 66 KB executable
`dist/barecode.pyz` with a `/usr/bin/env python3` shebang.

This also means **`pyproject.toml` has no `[build-system]` table at all** — not
even `setuptools`. A build backend is a dependency too, and omitting it makes the
empty manifest unambiguous at a glance.

**Gotcha we hit:** `zipapp`'s generated `__main__` **calls the entry callable and
discards its return value**, so an entry point that `return`s an exit code always
exits 0. We added `cli.run()`, which raises `SystemExit(main())`. Without it
`--fail-on` would be useless in CI, and Track A grades exit codes explicitly.

---

### 14. `importlib.metadata` (for the *running* interpreter) → direct `.dist-info` reads

**Normally:** `importlib.metadata.distributions()`.
**Instead:** we read the on-disk `.dist-info` layout ourselves.

`importlib.metadata` is stdlib and would have worked — for the *current*
interpreter. BareCode audits an **arbitrary target environment**, and doing that
through `importlib.metadata` would mean putting a foreign `site-packages` on
`sys.path`. We never import, execute, or launch anything from the environment
under audit. It is all file reads.

**Why this matters for the rules:** the hackathon forbids invoking a separately
installed tool at runtime, and explicitly permits *parsing files those tools
already produced* — provided it is disclosed here and degrades gracefully when
the files are absent. We never shell out to `pip`, `uv`, `poetry`, or anything
else. When there is no `RECORD`, we report the package as unverifiable rather
than failing.

---

### 15. `deptry` / `pipreqs` (import discovery) → `ast`

**Normally:** `deptry` or `pipreqs` to find which packages a codebase imports.
**Instead:** `ast.walk` over `ast.Import` / `ast.ImportFrom`, in
`src/barecode/project.py`.

Using the AST rather than a regex is the whole point: a module name inside a
string literal or a comment is never mistaken for an import, and `import os.path`
correctly reduces to `os`. Relative imports (`node.level > 0`) are skipped
because they can only resolve inside the project.

The harder half is mapping an import name to a distribution name — `import yaml`
comes from `pyyaml`, `import cv2` from `opencv-python`. Rather than carry a
hardcoded alias table that would be permanently out of date, we derive the map
from the installed layout: `top_level.txt` when the installer wrote one,
otherwise the first path segment of every `RECORD` entry. That is exact for the
environment in front of us, which is the only environment we make claims about.

---

### 16. `toml` / `tomli` (reading `pyproject.toml`) → `tomllib`

**Normally:** `toml` or `tomli` to read `pyproject.toml`.
**Instead:** `tomllib` (3.11+), in `src/barecode/project.py` and the proof script.

`tomli` was vendored into the standard library *as* `tomllib`, so this is the
same parser without the install.

**What we gave up:** `tomllib` is **read-only by design** and CPython has
declined to add a writer. We only read, so it costs us nothing — but a project
needing to *write* TOML has no stdlib option at all.

---

### 17. `filelock`, `watchdog`, `requests` → not needed at all

The most effective substitution is the one you don't make. BareCode is
offline-first by design: it makes **no network calls**, so there is no HTTP
client to replace. It reads a snapshot of the filesystem, so there is nothing to
watch. It holds no locks.

This is also why BareCode is not "a project requiring a running third-party
service," which the hackathon puts out of scope.

---

## Version floor

| Facility | Introduced | Used for |
|---|---|---|
| `hashlib.file_digest` | 3.11 | streaming RECORD verification |
| `enum.StrEnum` | 3.11 | `Verdict`, `Confidence` |
| `tomllib` | 3.11 | reading `pyproject.toml` in the proof script |
| `dataclass(slots=True)` | 3.10 | every model type |
| `sys.stdlib_module_names` | 3.10 | **the zero-dependency proof itself** |
| `os.process_cpu_count()` | 3.13 | thread pool sizing |
| `argparse(color=True)` | 3.14 | coloured `--help` (feature-detected, optional) |

Declared floor: **3.13**. Developed and tested on **3.14.4**. The `argparse`
colour argument is feature-detected at runtime rather than assumed.

---

## Where the standard library stopped

Being straight about the gaps, since they are the interesting half:

- **No marker evaluation.** See §6. `packaging` does this properly; we decline to
  guess rather than emit wrong edges.
- **No version-specifier comparison.** We report installed versions; we do not
  check whether they satisfy declared ranges. That needs PEP 440 comparison
  logic, which is a project in itself.
- **No YAML.** Not needed here, but worth stating: the standard library has no
  YAML parser at all, which is why `pyyaml` is listed as `none` in our own
  `killable` table.
- **No Unicode width tables.** See §3.
- **Legacy `.egg-info` distributions are not read.** Only `.dist-info`
  (PEP 376 / modern wheels). Anything installed by a pre-wheel toolchain is
  invisible to us. A real limitation, not a rounding error.
- **`RECORD` coverage is partial by nature.** `.pyc` files and `RECORD` itself
  carry no hash, so roughly a third of entries in a typical environment cannot be
  verified. We **count and display** those (`N entries carry no hash to check`)
  instead of quietly reporting a clean bill of health.

## Sources

Package→stdlib mappings in `src/barecode/advisor.py` are drawn from the CPython
standard library documentation and the swaps published on the
[Zero Dependency cheat sheets](https://zerodepshack.com/cheatsheets). Every entry
carries a confidence level, and the `none` rows exist specifically so the table
does not overclaim.
