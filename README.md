# BareCode

**Offline supply-chain X-ray for Python environments. Zero dependencies.**

[![zero-dependency proof](https://github.com/Deven-Kulthia/barecode/actions/workflows/ci.yml/badge.svg)](https://github.com/Deven-Kulthia/barecode/actions/workflows/ci.yml)

> Track A — Developer Tools & CLI · [Zero Dependency Hackathon 2026](https://zerodepshack.com/) · Team *Import Error*

```console
$ barecode verify
BareCode verify
  environment  : /tmp/project/.venv/lib/python3.14/site-packages
  packages     : 6 verified, 0 skipped
  files hashed : 596  (489 entries carry no hash to check)

  ✗ 1 finding(s) across 1 package(s)

  requests
    modified  requests/sessions.py
      content differs from the hash recorded at install
$ echo $?
1
```

That file was altered by **one character, with the file size left unchanged.**
Nothing else in the Python toolchain notices.

---

## The problem

Every wheel you install writes a `RECORD` file — a manifest of the SHA-256 of
every single file it placed on disk. Then nothing ever checks it again.

- `pip check` validates dependency *metadata* consistency, not file contents.
- `pip install --require-hashes` verifies the downloaded archive at install
  time, and never looks again.
- **There is no `pip verify`.**

So if anything inside `site-packages` changes after installation — a poisoned
post-install step, a malicious patch, a compromised mirror, a sync tool, a
colleague's "quick fix" in a shared environment — the standard toolchain is
silent. The 2026 ChainDrop worm poisoned ~444 packages with *valid build
provenance*: the metadata looked correct, because it was. Re-hashing the bytes on
disk is the check that catches that class of attack.

BareCode is that check, plus the four other questions you can't currently answer
without installing more packages to answer them.

## What it does

| Command | Question it answers |
|---|---|
| `barecode audit` | What's in this environment, who installed it, what came from outside an index, and does anything execute code at interpreter startup? |
| `barecode verify` | Do the installed files still match the hashes the installer recorded? |
| `barecode why <pkg>` | Why is this package here? Which paths pull it in? What breaks if it's compromised? |
| `barecode deps` | Do your declared, installed and actually-imported dependencies agree? |
| `barecode killable` | Which of these could the standard library replace, and which genuinely couldn't? |

Everything runs **fully offline.** No network calls, ever. Nothing from the
audited environment is imported or executed — it is all file reads.

## Install and run

Requires **Python ≥3.13** and nothing else. Developed and tested on 3.14.4.

```console
git clone https://github.com/Deven-Kulthia/barecode
cd barecode
make build            # one step -> dist/barecode.pyz (27 KB)
./dist/barecode.pyz audit
```

Optionally put it on your `PATH`:

```console
make install          # -> ~/.local/bin/barecode
```

Or skip the build entirely:

```console
python3 -m barecode --help      # with src/ on PYTHONPATH
```

There is no `pip install` step for **anything** — not to build it, not to run
it, not to test it.

## Usage

```console
$ barecode --help
usage: barecode [-h] [--version] <command> ...

Offline supply-chain X-ray for Python environments.

positional arguments:
  <command>
    audit     headline report: what is installed, where it came from, what
              looks wrong
    verify    re-hash installed files against the installer's RECORD (detects
              tampering)
    why       explain every reason a package is installed
    killable  which installed packages the standard library could replace
    deps      compare declared vs installed vs actually-imported dependencies

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit

Zero third-party dependencies. Run `make prove` to check that claim yourself.
```

Every command accepts:

| Flag | Effect |
|---|---|
| `-p, --path PATH` | project dir, virtualenv, or site-packages to inspect (default `.`) |
| `--json` | machine-readable output, guaranteed free of ANSI escapes |
| `--fail-on {info,warning,critical}` | minimum severity that exits 1 (default `warning`) |
| `-q, --quiet` | suppress the notes that go to stderr |
| `--no-color` | never emit colour (also honours `NO_COLOR`) |

`--path` accepts a project directory (it finds `.venv/`, `venv/`, `env/`), a
virtualenv root, or a `site-packages` directory directly. With no match it falls
back to the running interpreter and says so on stderr.

### Examples

```console
# audit the venv in the current project
barecode audit

# verify a specific environment, fail CI only on critical findings
barecode verify -p ./.venv --fail-on critical

# verify one package
barecode verify --only requests

# why is certifi installed, and what depends on it?
barecode why certifi --blast

# do declared, installed and imported agree?
barecode deps

# scan a source tree against a different environment
barecode deps --project ./src -p ./.venv

# machine-readable, for a CI gate
barecode verify --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["findings"]))'
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | clean — no findings at or above `--fail-on` |
| `1` | findings at or above the threshold |
| `2` | usage error (no command given) |
| `3` | environment could not be read, or the named package isn't installed |
| `130` | interrupted (SIGINT) |

Reports go to **stdout**; notes and diagnostics go to **stderr**, so `--json`
output stays pipeable even when something goes wrong.

## Sample output

```console
$ barecode audit
BareCode audit
  environment  : /usr/local/lib/python3.14/site-packages
  packages     : 190
  installers   : pip=190
  provenance   : 2 package(s) not from an index (git URL or local path)
                 internal-tooling
                 vendor-sdk
  startup code : 1 .pth file(s) execute code at interpreter startup
                 __editable__.foo.pth: import __editable___foo_finder
```

```console
$ barecode killable
  drop-in — the stdlib does the whole job
    click                  8.3.3        -> argparse (transitive)
      argparse has subparsers, type coercion, and coloured help in 3.14
    six                    1.17.0       -> nothing (transitive)
      Python 2 compatibility shim; delete it

  partial — covers the common path, gaps noted
    python-dateutil        2.9.0.post0  -> datetime.fromisoformat (transitive)
      3.11 parses most ISO 8601; arbitrary human formats it does not

  no stdlib equivalent — keep these
    pyyaml                 6.0.3        -> no equivalent
      no YAML in the stdlib. Use JSON or TOML, or write a subset parser
```

`killable` deliberately reports what **cannot** be replaced. A tool that claimed
everything was replaceable would be lying to you.

```console
$ barecode deps
BareCode deps
  project      : /tmp/depdemo
  declared in  : pyproject.toml
  declared     : 2 package(s)
  stdlib used  : 1 module(s)

  missing (1) — imported but not installed:
    nonexistent_lib          app.py

  unused (1) — declared but never imported:
    rich

  phantom (1) — installed but undeclared:
    pyjokes
```

Three sets that rarely agree. `missing` is an `ImportError` waiting for CI;
`unused` is a dependency you can probably delete; `phantom` works on your
machine and fails on a fresh install. Transitive dependencies of declared
packages are **not** reported as phantom — only packages nothing declared can
reach, which is what makes the finding trustworthy.

## Zero dependencies — verify it in five seconds

```console
$ make prove
BareCode — zero-dependency proof
================================================================
python              : 3.14.4  (297 stdlib modules known)
files scanned       : 8
ast nodes walked    : 11,354
distinct imports    : 24

stdlib imports      : 23 / 24
  __future__, argparse, ast, base64, collections, concurrent, contextlib,
  csv, dataclasses, email, enum, hashlib, io, json, os, pathlib, re, sys,
  sysconfig, tempfile, tomllib, typing, unittest
first-party imports : 1
  barecode
third-party imports : 0
  (none)

manifest            : empty
================================================================
RESULT: ZERO THIRD-PARTY DEPENDENCIES — manifest empty, every import is stdlib
```

A manifest describes *intent*. This checks *reality*: it AST-walks every source
file, collects every import, and asserts each is in `sys.stdlib_module_names` —
the frozen set CPython builds at compile time. It exits non-zero if anything else
ever appears, and it also asserts `pyproject.toml` declares no dependencies and
has no `[build-system]` table. The proof script is itself subject to the proof.

Pre-generated output is committed as [`deps-proof.txt`](deps-proof.txt), and the
same two checks run on a clean GitHub runner on every push — see the badge above.
That workflow contains **no `pip install` step at all**; its only setup is a
Python interpreter, so it would go red the moment a third-party import appeared.

See **[STDLIB.md](STDLIB.md)** for all 17 package→stdlib substitutions, and
**[PACKAGE-KILLER.md](PACKAGE-KILLER.md)** for the feature comparison against
the tools BareCode replaces.

## Reproducible build

```console
$ make repro
  build 1: c28da598fb7c3696595140cea49c8741afa9da42cb7d562e4d09490da896ec12
  build 2: c28da598fb7c3696595140cea49c8741afa9da42cb7d562e4d09490da896ec12

  BYTE-IDENTICAL — reproducible build verified
```

Builds the artifact twice from a clean tree and asserts the results are
byte-identical, printing both hashes. **Scope: same machine, same toolchain** —
cross-environment reproducibility is not claimed, because a fresh `git clone`
sets new file mtimes and `zipapp` stores those in the archive.

One non-obvious detail this target had to handle: a leftover `__pycache__` gets
deleted during the first build, which bumps `src/barecode/`'s directory mtime and
makes build 2 differ through no fault of the source. `make repro` therefore starts
from `make clean`. The same reason is why `make build` strips `__pycache__` before
zipping at all — otherwise the artifact is 66 KB or 170 KB depending on whether
you ran the tests first.

## Reproduce the tamper detection yourself

```console
$ ./scripts/demo.sh setup      # builds a throwaway venv with requests in it
$ barecode verify -p /tmp/barecode-demo     # clean -> exit 0
$ ./scripts/demo.sh poison     # changes ONE character, file size unchanged
$ barecode verify -p /tmp/barecode-demo     # modified -> exit 1
$ ./scripts/demo.sh restore
```

The poison step edits a single byte in `requests/sessions.py` while preserving
the file's length, so size and mtime both still look plausible. Only re-hashing
finds it.

## Architecture

```
cli.py         argparse subcommands, exit codes, JSON/human rendering
  ├── env.py         scan .dist-info: METADATA (email.parser), INSTALLER,
  │                  direct_url.json provenance, .pth startup hooks, and the
  │                  import-name -> distribution map derived from RECORD
  ├── integrity.py   re-hash RECORD entries (csv + hashlib.file_digest,
  │                  parallelised with concurrent.futures)
  ├── graph.py       PEP 508 requirement parsing, BFS `why` + blast radius
  ├── project.py     declared deps (tomllib + requirements parser) vs actual
  │                  imports (ast), and the three-way comparison
  ├── advisor.py     curated package -> stdlib table with confidence levels
  └── ansi.py        SGR styling, NO_COLOR/TTY precedence, width measurement

tools/prove_zero_deps.py   the dependency proof (ast + sys.stdlib_module_names)
tests/test_barecode.py     79 tests over synthetic .dist-info fixtures
.github/workflows/ci.yml   the same proof, on a clean runner, no pip install
```

Data flows one way: scan → model → analyse → render. Analyzers never touch the
filesystem directly and renderers never compute anything, which is why the
`--json` and human paths cannot disagree.

## Security

BareCode's job is inspecting untrusted directories, so the threat model matters.

- **Nothing is executed.** We never import from, or launch anything in, the
  audited environment. `.pth` files that execute code are *detected and
  reported*, never run.
- **Path containment.** `RECORD` is attacker-controllable in a poisoned package.
  A recorded path resolving outside the environment root is reported as a
  `escapes-environment` critical finding rather than followed. The boundary is
  the environment root, not `site-packages`, because console scripts are
  legitimately recorded as `../../../bin/foo`.
- **No shelling out.** We never invoke `pip`, `git`, `uv`, or any other
  process. This is both a hackathon rule and the right design: an auditing tool
  that runs the thing it audits has already lost.
- **No network.** Nothing to exfiltrate to, nothing to be MITM'd.
- **Degrades rather than fails.** Missing `RECORD`, unreadable directories, and
  malformed `METADATA` produce reported findings, not tracebacks.
- **No secret handling.** BareCode reads no credentials and writes no state.

Hashing is `hashlib` (SHA-256) throughout. No cryptography is invented here —
we verify digests the installer already computed.

## Performance

Measured on a real 190-package environment (Apple Silicon, Python 3.14.4).
Times are wall clock for the whole process, including interpreter startup and
unpacking the zipapp — not just the analysis:

| Workload | Result |
|---|---|
| `audit` — 190 packages | ~0.8 s |
| `verify` — 190 packages, **4,927 files hashed** | **3.4 s** |
| `killable` — graph over 190 packages | ~0.5 s |
| Artifact size | 27 KB |

`verify` is I/O bound. `hashlib.file_digest` releases the GIL while reading, so a
`ThreadPoolExecutor` sized from `os.process_cpu_count()` gives real parallelism.
Files whose recorded size already differs are flagged without being hashed.

## Testing

```console
$ make test
Ran 79 tests in 1.34s
OK
```

Stdlib `unittest`, no plugins. Fixtures are **synthesised on disk** — real
`.dist-info` directories with real RECORD hashes in a `TemporaryDirectory` — so
the suite is hermetic, offline, and never calls `pip`.

Covered: clean installs; appended bytes; **same-length single-character edits**;
deleted files; `RECORD` paths escaping the environment; console scripts outside
`site-packages` (a false-positive regression we actually hit); quoted CSV paths
containing commas; unhashed entries; missing `RECORD`; RFC 2047-encoded METADATA
headers; multi-line licence fields; unreadable directories; dependency cycles;
requirements on uninstalled packages; PEP 503 normalisation; PEP 508 parse forms;
PEP 621 and Poetry dependency tables; `requirements.txt` comments, options,
markers and `-r` include cycles; import names that differ from distribution names
(`import yaml` → `pyyaml`); module names appearing in strings and comments;
transitive deps *not* being flagged as phantom; every exit code; `--fail-on`
thresholds; JSON validity on all five commands; absence of ANSI escapes in JSON;
stdout/stderr separation; `NO_COLOR`.

`make check` runs the proof and the tests together — that's what CI gates on.

## Limitations

Stated plainly, because a naive-but-honest tool is worth more than a
hand-wavy one:

- **`.dist-info` only.** Legacy `.egg-info` distributions are invisible to us.
- **`RECORD` coverage is partial by nature.** `RECORD` itself and `.pyc` files
  carry no hash, so roughly a third of entries in a typical environment cannot be
  verified. We print that count rather than implying a clean bill of health.
- **A rewritten `RECORD` defeats verification.** An attacker with write access to
  `site-packages` can update the hashes to match their payload. Detecting that
  requires an out-of-band record (a lockfile with hashes, or a signed SBOM);
  BareCode compares disk against the installer's own claim, which catches
  everything that alters files without also rewriting the manifest.
- **No PEP 508 marker evaluation and no PEP 440 version comparison.** We record
  markers verbatim and label edges conditional rather than guessing. See
  STDLIB.md §6.
- **No CJK width handling** in column alignment. See STDLIB.md §3.
- **Lockfiles are not read as declarations.** `poetry.lock` / `uv.lock` enumerate
  the full transitive closure, so treating them as "declared" would make every
  transitive package look intentional and destroy the unused/phantom
  comparison. `deps` reads `pyproject.toml` and `requirements*.txt` only.
- **`deps` cannot see dynamic imports.** `importlib.import_module(name)` with a
  computed name is invisible to static analysis, so it may show up as `unused`.

## Licence

MIT — see [LICENSE](LICENSE).
