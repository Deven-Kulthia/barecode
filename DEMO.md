# DEMO.md — 5-minute video script

Read this aloud while running the commands. Total: 5:00.

**Before you hit record**

```console
cd barecode
./scripts/demo.sh setup        # builds /tmp/barecode-demo, takes ~15s
make build
clear
```

Terminal font large. Window wide enough that no line wraps.

---

## 0:00 – 0:30 · The problem

> "Every Python wheel you install writes a RECORD file — a list of the SHA-256
> of every file it put on disk. Then nothing ever checks it again.
> `pip check` only validates metadata. `--require-hashes` checks the download,
> once, at install time. There is no `pip verify`.
> So if anything in site-packages changes *after* install, nothing tells you.
> Last month, ChainDrop poisoned about 444 packages with valid build
> provenance. The metadata was correct. The files were not."

## 0:30 – 1:00 · Why this normally costs you dependencies

> "To answer that, and 'why is this package even here', the normal advice is:
> pip install pipdeptree, pip-licenses, deptry. Four more packages, with their
> own dependencies, added to the environment you were trying to audit.
> An auditing tool that arrives through the channel you're auditing isn't
> independent. So I built BareCode — one file, zero dependencies."

## 1:00 – 3:30 · Live demo

```console
barecode audit -p /tmp/barecode-demo
```
> "What's installed, who installed it, licences, and whether anything executes
> code at interpreter startup — that last one is Python's answer to npm's
> postinstall hooks, and almost nobody checks it."

```console
barecode why certifi -p /tmp/barecode-demo --blast
```
> "Why is certifi here — every path that pulls it in, shortest first. And
> --blast: everything that breaks if it's compromised."

```console
barecode verify -p /tmp/barecode-demo
```
> "Clean. Six hundred and twenty-one files across seven packages, re-hashed
> against RECORD. Exit zero."

**← THE MOMENT. Do this slowly.**

```console
./scripts/demo.sh poison
```
> "Now I'm going to change exactly one character inside requests — and keep the
> file size identical. Size unchanged, modification time plausible. This is what
> a real supply-chain attack looks like."

```console
barecode verify -p /tmp/barecode-demo ; echo "exit: $?"
```
> "Caught. The exact file, and exit code 1 — so this gates CI."

```console
barecode deps --project /tmp/barecode-deps-demo -p /tmp/barecode-demo
```
> "Declared, installed, and actually imported — three sets that rarely agree.
> Missing is an ImportError waiting for CI. Unused you can delete. Phantom works
> on your machine and fails on a fresh install."

```console
barecode killable
```
> "And which of these does the standard library already replace. Note the last
> section — no stdlib equivalent, keep these. A tool that claimed everything was
> replaceable would be lying to you."

## 3:30 – 4:15 · The engineering underneath

```console
wc -l src/barecode/*.py
```
> "About a thousand lines. `packaging` replaced by email.parser, because wheel
> METADATA genuinely is RFC 822. `networkx` replaced by a dict and a BFS.
> `colorama` by raw ANSI that honours NO_COLOR. RECORD is parsed with the csv
> module, not split on commas — paths with commas are quoted, and getting that
> wrong invents missing files.
> The import-name-to-package map — `import yaml` means `pyyaml` — is derived
> from RECORD itself, so it can never go stale."

## 4:15 – 4:45 · Zero-dependency proof

```console
cat pyproject.toml | head -20
make prove
```
> "Empty manifest. No build-system table either — a build backend is a
> dependency too. But a manifest is only intent, so `make prove` checks reality:
> it AST-walks every source file and asserts every single import is in
> sys.stdlib_module_names, the list CPython builds at compile time. Twenty-three
> stdlib modules. Zero third-party. Non-zero exit if that ever changes — and it
> runs in CI on a clean machine on every push."

## 4:45 – 5:00 · Tests, repro, and the punchline

```console
make test 2>&1 | tail -3
make repro 2>&1 | tail -4
```
> "Seventy-nine tests, standard library unittest, no pytest. Built twice,
> byte-identical."

```console
barecode deps -p .
```
> "And finally, BareCode inspecting itself: zero declared dependencies,
> twenty-three standard library modules, everything agrees. The tool that
> measures dependency risk doesn't have any."

---

## Cleanup after recording

```console
./scripts/demo.sh restore
./scripts/demo.sh clean
```

## If something goes wrong mid-take

- `verify` shows findings when it should be clean → `./scripts/demo.sh restore`
- Colour looks wrong when recording → `export FORCE_COLOR=1`
- `/tmp/barecode-deps-demo` missing → skip the `deps` beat; it is the least essential
