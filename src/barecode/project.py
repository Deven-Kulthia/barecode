"""Read a project's *declared* dependencies and its *actual* imports.

Three sets rarely agree, and every disagreement is a real problem:

    declared   what the project says it needs   (pyproject.toml, requirements.txt)
    installed  what is in the environment       (env.py)
    imported   what the source code imports     (this module, via ast)

    declared - imported   ->  unused: dependency you can probably delete
    imported - installed  ->  missing: an ImportError waiting to happen
    installed - declared* ->  phantom: works on your machine, not in CI

(*) "declared" for the phantom comparison means the *transitive closure* of what
is declared. A package pulled in as a dependency of a declared package is not
phantom -- that is simply how packaging works. Only something reachable from
nothing at all is.

Normally: ``deptry`` / ``pip-check`` / ``pipreqs``.
Instead:   ``tomllib`` for pyproject, a small line parser for requirements.txt,
           and ``ast`` for imports.

Import detection uses the AST rather than a regex, so a module name inside a
string or a comment is never mistaken for an import.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from .env import normalise
from .graph import Requirement, parse_requirement

# Present in essentially every virtualenv and never declared by a project.
BOOTSTRAP = frozenset({"pip", "setuptools", "wheel", "pkg-resources", "distribute", "uv"})

# Directories that are never project source.
SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", ".env",
        "node_modules", ".tox", ".nox", "build", "dist", ".mypy_cache",
        ".pytest_cache", ".ruff_cache", "site-packages", ".eggs",
    }
)


@dataclass(slots=True)
class Declared:
    names: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def declared_dependencies(project: Path) -> Declared:
    """Direct dependencies a project declares.

    Lockfiles are deliberately not read here: they enumerate the full transitive
    closure, so treating them as "declared" would make every transitive package
    look intentional and defeat the unused/phantom comparison.
    """
    result = Declared()
    pyproject = project / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            result.problems.append(f"pyproject.toml: {exc}")
            data = {}

        project_table = data.get("project", {})
        found = False
        for line in project_table.get("dependencies", []) or []:
            req = parse_requirement(line)
            if req:
                result.names.add(req.name)
                found = True
        for deps in (project_table.get("optional-dependencies") or {}).values():
            for line in deps or []:
                req = parse_requirement(line)
                if req:
                    result.names.add(req.name)
                    found = True

        # Poetry keeps dependencies in its own table.
        poetry = (data.get("tool") or {}).get("poetry") or {}
        for group in (poetry.get("dependencies") or {}, *[
            g.get("dependencies") or {} for g in (poetry.get("group") or {}).values()
        ]):
            for name in group:
                if name.lower() != "python":
                    result.names.add(normalise(name))
                    found = True

        if found or "project" in data:
            result.sources.append("pyproject.toml")

    for candidate in sorted(project.glob("requirements*.txt")):
        names, problems = _read_requirements(candidate, project, seen=set())
        if names or problems:
            result.names |= names
            result.problems += problems
            result.sources.append(candidate.name)

    return result


def _read_requirements(path: Path, root: Path, seen: set[Path]) -> tuple[set[str], list[str]]:
    """Parse a requirements file, following `-r` includes once each."""
    resolved = path.resolve()
    if resolved in seen:
        return set(), []
    seen.add(resolved)

    names: set[str] = set()
    problems: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        return set(), [f"{path.name}: {exc}"]

    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            include = root / line.split(None, 1)[1].strip()
            if include.exists():
                sub, subproblems = _read_requirements(include, root, seen)
                names |= sub
                problems += subproblems
            continue
        if line.startswith("-"):
            continue  # --index-url, --find-links, -e, and friends
        req = parse_requirement(line)
        if req:
            names.add(req.name)
    return names, problems


def imported_modules(project: Path) -> dict[str, list[str]]:
    """Top-level modules imported by the project's own source, and where.

    Relative imports are skipped -- they can only resolve inside the project.
    """
    found: dict[str, list[str]] = defaultdict(list)
    for path in _source_files(project):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
            continue  # not our source to fix; skip rather than fail the run
        rel = path.relative_to(project).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found[alias.name.partition(".")[0]].append(rel)
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                found[node.module.partition(".")[0]].append(rel)
    return dict(found)


def _source_files(project: Path) -> list[Path]:
    files: list[Path] = []
    stack = [project]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue  # avoid symlink loops and escaping the project tree
            if entry.is_dir():
                if entry.name not in SKIP_DIRS and not entry.name.endswith(".egg-info"):
                    stack.append(entry)
            elif entry.suffix == ".py":
                files.append(entry)
    return sorted(files)


def first_party_names(project: Path) -> set[str]:
    """Top-level names the project itself provides, so they aren't 'missing'."""
    names: set[str] = set()
    for base in (project, project / "src"):
        if not base.is_dir():
            continue
        try:
            entries = list(base.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir() and (entry / "__init__.py").exists() and entry.name not in SKIP_DIRS:
                names.add(entry.name)
            elif entry.suffix == ".py":
                names.add(entry.stem)
    return names


@dataclass(slots=True)
class DepReport:
    declared: Declared
    unused: list[str]
    missing: dict[str, list[str]]
    phantom: list[str]
    stdlib_used: list[str]

    @property
    def clean(self) -> bool:
        return not (self.unused or self.missing or self.phantom)


def _reachable(roots: set[str], edges: dict[str, list[Requirement]]) -> set[str]:
    """Forward transitive closure over the installed dependency graph."""
    seen: set[str] = set()
    queue = deque(roots)
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        for req in edges.get(current, ()):
            if req.name not in seen:
                queue.append(req.name)
    return seen


def analyse(
    project: Path,
    installed: dict[str, str],
    installed_names: set[str],
    edges: dict[str, list[Requirement]] | None = None,
) -> DepReport:
    """Compare declared, installed and imported.

    `installed` maps import name -> distribution name (from env.provides_map).
    `edges` is the forward dependency graph (from graph.build), used to exclude
    legitimate transitive dependencies from the phantom set.
    """
    declared = declared_dependencies(project)
    imports = imported_modules(project)
    ours = first_party_names(project)
    stdlib = frozenset(sys.stdlib_module_names)

    used_dists: set[str] = set()
    missing: dict[str, list[str]] = {}
    stdlib_used: set[str] = set()

    for module, files in imports.items():
        if module in ours:
            continue
        if module in stdlib:
            stdlib_used.add(module)
            continue
        dist = installed.get(module)
        if dist:
            used_dists.add(dist)
        else:
            missing[module] = sorted(set(files))

    unused = sorted(declared.names - used_dists)

    # Phantom only makes sense when the project declares something to compare
    # against, and only for packages nothing declared can reach.
    if declared.names:
        expected = _reachable(declared.names | used_dists, edges or {}) | BOOTSTRAP
        phantom = sorted(installed_names - expected)
    else:
        phantom = []

    return DepReport(
        declared=declared,
        unused=unused,
        missing=missing,
        phantom=phantom,
        stdlib_used=sorted(stdlib_used),
    )
