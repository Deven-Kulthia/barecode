# PACKAGE-KILLER.md

**Bonus claim: Package Killer (+3)** — Zero Dependency Hackathon 2026, Track A.

BareCode replaces tools you would otherwise `pip install` to inspect your own
environment. This document states exactly what it replaces, exactly what it does
*not*, and why an auditing tool in particular has no business adding
dependencies.

---

## The irony this fixes

To answer "what is in my environment and is it safe", the normal advice is to
install more packages:

```console
pip install pipdeptree pip-licenses deptry johnnydep
```

That is four new distributions, plus their transitive dependencies, added to the
very environment you were trying to audit. Every one of them is a new
maintainer account that can be phished, a new release that can be poisoned, and
new code running inside your interpreter. The 2026 ChainDrop worm compromised a
maintainer account and shipped ~444 poisoned packages *with valid build
provenance* — an auditing tool that arrives through the same channel it is
auditing offers no independent assurance.

BareCode is a single 66 KB file with an empty manifest. It cannot be
supply-chain-attacked through its dependencies because it has none.

```console
$ make prove
third-party imports : 0
RESULT: ZERO THIRD-PARTY DEPENDENCIES — manifest empty, every import is stdlib
```

---

## Primary kill: `pipdeptree`

`pipdeptree` is the standard answer to "why is this package installed" and one
of the most-installed dependency-inspection tools on PyPI. (Judges can confirm
current figures at [pypistats.org/packages/pipdeptree](https://pypistats.org/packages/pipdeptree).)

Its core value is `pipdeptree --reverse --packages <name>`. That is
`barecode why <name>`.

| Capability | `pipdeptree` | BareCode | Notes |
|---|---|---|---|
| Forward dependency tree | ✅ | ⚠️ partial | We expose the graph and paths, not a rendered full tree |
| **Reverse lookup ("why is this here")** | ✅ | ✅ `why` | Ours returns **all paths, shortest first**, not just direct requirers |
| Blast radius (full transitive reverse closure) | ❌ | ✅ `why --blast` | |
| Distinguishes direct vs transitive installs | ✅ | ✅ | |
| JSON output | ✅ | ✅ `--json` | |
| Cycle-safe traversal | ✅ | ✅ | Tested explicitly |
| DOT / graphviz export | ✅ | ❌ | Requires graphviz anyway |
| Dependency conflict detection | ✅ | ❌ | Needs PEP 440 comparison — see *Limitations* |
| PEP 508 marker evaluation | ✅ | ❌ (by choice) | We record markers verbatim rather than guess |
| Runs without being installed into the target env | ❌ | ✅ | `pipdeptree` inspects *its own* interpreter |
| **Third-party dependencies** | several | **zero** | |

One genuine advantage beyond dependency count: `pipdeptree` inspects the
interpreter it is installed into, so auditing a project's venv means installing
`pipdeptree` into that venv — mutating what you are measuring. BareCode points at
any environment from outside with `-p`, and never imports from it.

## Secondary kill: `pip-licenses`

| Capability | `pip-licenses` | BareCode |
|---|---|---|
| Licence roll-up across the environment | ✅ | ✅ (in `audit`) |
| Grouping / counts per licence | ✅ | ✅ |
| Flags undeclared licences | ✅ | ✅ `(undeclared)` |
| Handles PEP 639 `License-Expression` | ✅ | ✅ preferred over legacy `License` |
| Normalises free-text licence blobs | ⚠️ | ✅ `(unstructured text)` bucket |
| Per-format output (HTML, RST, Markdown…) | ✅ | ❌ JSON and text only |
| Licence *compatibility* analysis | ❌ | ❌ |

Real environments contain packages that inline an entire licence document — or an
ASCII banner — into the free-text `License:` header. We bucket those rather than
printing a 400-character "licence name".

## Third kill: `deptry` / `pipreqs` / `pip-check`

`barecode deps` compares three sets that rarely agree — declared, installed, and
actually imported.

| Capability | `deptry` | `pipreqs` | BareCode |
|---|---|---|---|
| Unused declared dependencies | ✅ | ❌ | ✅ |
| Imported but not installed | ✅ | ❌ | ✅ |
| Installed but undeclared ("phantom") | ✅ | ❌ | ✅ |
| Generates a requirements file from imports | ❌ | ✅ | ❌ |
| AST-based (not regex) import detection | ✅ | ⚠️ | ✅ |
| Import name → distribution mapping | via table | via table | **derived from installed `RECORD`/`top_level.txt`** |
| Excludes legitimate transitive deps from phantom | ✅ | — | ✅ |
| PEP 621 + Poetry + `requirements*.txt` | ✅ | ⚠️ | ✅ |
| Follows `-r` includes (cycle-safe) | ✅ | ❌ | ✅ |
| **Third-party dependencies** | several | several | **zero** |

One design difference worth stating: mapping `import yaml` to the `pyyaml`
distribution normally needs a maintained alias table. We derive it from the
environment itself — `top_level.txt` when the installer wrote one, otherwise the
first path segment of each `RECORD` entry. That is exact for the environment in
front of us and can never go stale, though it means we can say nothing about a
package that is not installed.

## Not a kill — a gap: `verify`

There is no package to replace for `barecode verify`, because **nothing does
this**:

| Tool | What it checks |
|---|---|
| `pip check` | dependency metadata consistency — not file contents |
| `pip install --require-hashes` | the downloaded archive, at install time only |
| `pip-audit` | installed versions against a vulnerability database (needs network) |
| **`barecode verify`** | **the bytes on disk, against the hashes the installer recorded** |

Every wheel writes a `RECORD` file containing the SHA-256 of every file it
installed. Nothing re-reads it. `barecode verify` does, and catches a
same-length single-character edit that leaves file size and mtime plausible:

```console
$ barecode verify
  requests
    modified  requests/sessions.py
      content differs from the hash recorded at install
$ echo $?
1
```

This is the part we would claim as the novel contribution rather than the
reimplementation.

## Also replaced, inside BareCode's own implementation

Building this without dependencies meant replacing the libraries a tool like
this normally imports. Fully documented in **[STDLIB.md](STDLIB.md)** — 17
substitutions with rationale and limitations. The headline ones:

| Normally | Instead |
|---|---|
| `click` / `typer` | `argparse` with subparsers |
| `colorama` / `rich` | raw ANSI SGR + `NO_COLOR`/TTY precedence |
| `packaging` (METADATA, PEP 503, PEP 508) | `email.parser`, `re` |
| `networkx` | `dict` adjacency + `collections.deque` BFS |
| `deptry` / `pipreqs` (import discovery) | `ast` |
| `toml` / `tomli` | `tomllib` |
| `pytest` | `unittest` (79 tests) |
| `pyinstaller` / `shiv` | `zipapp` |

## Limitations — what the killed tools still do better

Stated plainly, because the hackathon rewards honesty over hand-waving and a
feature matrix with no ❌ column is marketing:

- **No PEP 440 version comparison**, so no dependency-conflict detection.
  `pipdeptree` will tell you `A requires B>=2.0` while `B==1.4` is installed.
  We will not. That needs a correct version-comparison implementation, which is
  a project of its own.
- **No PEP 508 marker evaluation.** `pipdeptree` resolves conditional
  dependencies; we label the edge conditional and record the marker verbatim.
  Deliberate: a wrong edge is worse than an absent one.
- **No rendered forward tree.** We give paths and adjacency, not an indented
  full-tree view.
- **No DOT export, no HTML/RST licence formats.**
- **No vulnerability data.** `pip-audit` queries OSV; BareCode makes no network
  calls at all, by design. These are complementary, not competing.
- **`.dist-info` only** — legacy `.egg-info` installs are invisible to us.
- **A rewritten `RECORD` defeats `verify`.** We compare disk against the
  installer's own claim, which catches anything that alters files without also
  rewriting the manifest. Detecting a rewritten manifest needs an out-of-band
  record.

## Why zero dependencies matters here specifically

For most tools, "zero dependencies" is a nice property. For a supply-chain
auditor it is a correctness argument:

1. **No circularity.** A tool that adds four distributions to audit four hundred
   has made the problem it measures slightly worse.
2. **Independent trust.** Assurance about a compromised environment should not
   arrive through the same package channel that was compromised.
3. **It runs where you need it.** No install step means it works in a locked-down
   CI image, an air-gapped box, or a container you cannot `pip install` into.
   Copy one 66 KB file.
4. **It is auditable in an afternoon.** ~1,000 lines of stdlib Python you can
   read end to end. You cannot say that about the transitive closure of four
   inspection tools.
