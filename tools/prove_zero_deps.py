#!/usr/bin/env python3
"""Machine-checked proof that BareCode has zero third-party dependencies.

A dependency manifest describes *intent*. This script checks *reality*: it
parses every source file with the standard library's own `ast` module, collects
every top-level module that is actually imported, and asserts that each one is
a member of `sys.stdlib_module_names` -- the frozen set CPython builds at
compile time listing exactly what ships in the box.

Two independent assertions must both hold:

  1. MANIFEST  pyproject.toml declares no runtime and no optional dependencies.
  2. SOURCE    every import resolves to the standard library or to BareCode
               itself. Nothing else. No exceptions, no allowlist.

Exit status
-----------
0   both assertions hold
1   a violation was found (or a source file failed to parse)
2   usage error

Usage
-----
    python3 tools/prove_zero_deps.py
    python3 tools/prove_zero_deps.py --json
    python3 tools/prove_zero_deps.py --list          # stdlib modules in use
    python3 tools/prove_zero_deps.py --write deps-proof.txt

This script is itself subject to the proof: it imports only stdlib.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE_ROOTS = ("src", "tools", "tests")

# Deliberately no allowlist. Every import is checked against
# sys.stdlib_module_names and nothing else -- an escape hatch here would defeat
# the entire point of the proof.


def first_party_names(repo: Path) -> set[str]:
    """Top-level importable names that BareCode itself provides."""
    src = repo / "src"
    if not src.is_dir():
        return set()
    names = set()
    for child in src.iterdir():
        if child.is_dir() and (child / "__init__.py").exists():
            names.add(child.name)
        elif child.suffix == ".py":
            names.add(child.stem)
    return names


def python_files(repo: Path) -> list[Path]:
    files: list[Path] = []
    for root in SOURCE_ROOTS:
        base = repo / root
        if base.is_dir():
            files.extend(sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts))
    return files


def imports_in(path: Path) -> tuple[set[str], int]:
    """Top-level module names imported by `path`, plus a statement count.

    Relative imports (`from . import x`) are skipped: they can only ever
    resolve inside this project, so they cannot introduce a dependency.
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.partition(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative -- always first-party
                continue
            if node.module:
                found.add(node.module.partition(".")[0])
    return found, sum(1 for _ in ast.walk(tree))


def check_manifest(repo: Path) -> list[str]:
    """Assertion 1: the declared manifest is empty."""
    pyproject = repo / "pyproject.toml"
    if not pyproject.exists():
        return ["pyproject.toml is missing -- cannot verify the manifest"]
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data.get("project", {})
    problems = []
    runtime = project.get("dependencies", [])
    if runtime:
        problems.append(f"pyproject.toml declares {len(runtime)} runtime dependencies: {runtime}")
    for extra, deps in (project.get("optional-dependencies") or {}).items():
        if deps:
            problems.append(f"pyproject.toml extra '{extra}' declares dependencies: {deps}")
    if "build-system" in data:
        requires = data["build-system"].get("requires", [])
        if requires:
            problems.append(f"[build-system] requires {requires} -- build backends are a dependency too")
    return problems


def run(repo: Path) -> dict:
    stdlib = frozenset(sys.stdlib_module_names)
    ours = first_party_names(repo)
    files = python_files(repo)

    users: dict[str, list[str]] = defaultdict(list)  # module -> files importing it
    statements = 0
    parse_errors: list[str] = []

    for path in files:
        rel = path.relative_to(repo).as_posix()
        try:
            found, count = imports_in(path)
        except (SyntaxError, UnicodeDecodeError) as exc:
            parse_errors.append(f"{rel}: {exc}")
            continue
        statements += count
        for name in found:
            users[name].append(rel)

    used_stdlib = sorted(n for n in users if n in stdlib)
    used_ours = sorted(n for n in users if n in ours and n not in stdlib)
    third_party = sorted(n for n in users if n not in stdlib and n not in ours)

    manifest_problems = check_manifest(repo)
    ok = not third_party and not parse_errors and not manifest_problems

    return {
        "ok": ok,
        "files_scanned": len(files),
        "ast_nodes": statements,
        "distinct_imports": len(users),
        "stdlib": used_stdlib,
        "first_party": used_ours,
        "third_party": {name: users[name] for name in third_party},
        "manifest_problems": manifest_problems,
        "parse_errors": parse_errors,
        "python": sys.version.split()[0],
        "stdlib_module_count": len(sys.stdlib_module_names),
    }


def render(r: dict) -> str:
    lines = [
        "BareCode — zero-dependency proof",
        "=" * 64,
        f"python              : {r['python']}  ({r['stdlib_module_count']} stdlib modules known)",
        f"files scanned       : {r['files_scanned']}",
        f"ast nodes walked    : {r['ast_nodes']:,}",
        f"distinct imports    : {r['distinct_imports']}",
        "",
        f"stdlib imports      : {len(r['stdlib'])} / {r['distinct_imports']}",
        f"  {', '.join(r['stdlib']) or '(none)'}",
        f"first-party imports : {len(r['first_party'])}",
        f"  {', '.join(r['first_party']) or '(none)'}",
        f"third-party imports : {len(r['third_party'])}",
    ]
    if r["third_party"]:
        for name, where in r["third_party"].items():
            lines.append(f"  !! {name}  imported by: {', '.join(where)}")
    else:
        lines.append("  (none)")

    lines += ["", f"manifest            : {'empty' if not r['manifest_problems'] else 'PROBLEM'}"]
    for problem in r["manifest_problems"]:
        lines.append(f"  !! {problem}")
    for err in r["parse_errors"]:
        lines.append(f"  !! parse error: {err}")

    lines += ["", "=" * 64]
    lines.append(
        "RESULT: ZERO THIRD-PARTY DEPENDENCIES — manifest empty, every import is stdlib"
        if r["ok"]
        else "RESULT: FAILED — see the !! lines above"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="prove_zero_deps",
        description="Assert that BareCode imports nothing outside the standard library.",
    )
    ap.add_argument("--json", action="store_true", help="emit the full result as JSON")
    ap.add_argument("--list", action="store_true", help="list only the stdlib modules in use")
    ap.add_argument("--write", metavar="FILE", help="also write the human-readable report to FILE")
    args = ap.parse_args(argv)

    result = run(REPO)

    if args.list:
        print("\n".join(result["stdlib"]))
    elif args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render(result))

    if args.write:
        (REPO / args.write).write_text(render(result) + "\n", encoding="utf-8")

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
