"""Dependency graph over the installed environment, and the `why` query.

Normally: ``packaging.requirements`` (PEP 508 parsing) + ``networkx`` (graph).
Instead:   ``re`` for the requirement grammar we actually need, plain dicts for
           adjacency, and ``collections.deque`` for breadth-first search.

`networkx` would be a large dependency for something that is, honestly, a dict
of lists and a BFS. The PEP 508 grammar is the more interesting half: we parse
name, extras, version specifier and environment marker, but we deliberately do
*not* evaluate markers. Evaluating `python_version < "3.11" and extra == "dev"`
correctly needs the full marker grammar; guessing at it would produce edges
that are quietly wrong. Instead we record the marker verbatim and label the
edge conditional, which is honest about what we know.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass

from .env import Environment, normalise

# PEP 508, reduced to the four parts we use. Full grammar includes URL specs
# (`name @ https://...`), which we capture as part of the specifier.
_REQ = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)      # distribution name
    \s*(?:\[(?P<extras>[^\]]*)\])?            # optional [extra1,extra2]
    \s*(?P<spec>[^;]*?)                       # version specifier or @ url
    \s*(?:;\s*(?P<marker>.*))?                # environment marker
    $""",
    re.VERBOSE,
)


@dataclass(slots=True, frozen=True)
class Requirement:
    name: str  # normalised
    raw: str
    extras: tuple[str, ...] = ()
    specifier: str = ""
    marker: str = ""

    @property
    def conditional(self) -> bool:
        return bool(self.marker)

    @property
    def extra_only(self) -> bool:
        """True when this requirement only applies if an extra was requested."""
        return "extra" in self.marker


def parse_requirement(line: str) -> Requirement | None:
    match = _REQ.match(line.strip())
    if not match:
        return None
    extras = match.group("extras") or ""
    return Requirement(
        name=normalise(match.group("name")),
        raw=line.strip(),
        extras=tuple(e.strip() for e in extras.split(",") if e.strip()),
        specifier=(match.group("spec") or "").strip(),
        marker=(match.group("marker") or "").strip(),
    )


@dataclass(slots=True)
class Graph:
    """Adjacency over installed packages only.

    A requirement naming something that is not installed is not an edge -- it is
    a *missing* dependency, tracked separately so `audit` can report it.
    """

    edges: dict[str, list[Requirement]]
    reverse: dict[str, list[str]]
    missing: dict[str, list[Requirement]]

    @property
    def roots(self) -> list[str]:
        """Packages nothing else depends on -- what you actually asked for."""
        return sorted(n for n in self.edges if not self.reverse.get(n))


def build(env: Environment) -> Graph:
    edges: dict[str, list[Requirement]] = {name: [] for name in env.packages}
    reverse: dict[str, list[str]] = {name: [] for name in env.packages}
    missing: dict[str, list[Requirement]] = {}

    for name, pkg in env.packages.items():
        for line in pkg.requires:
            req = parse_requirement(line)
            if req is None:
                continue
            if req.name in env.packages:
                edges[name].append(req)
                reverse[req.name].append(name)
            else:
                missing.setdefault(name, []).append(req)

    for targets in reverse.values():
        targets.sort()
    return Graph(edges=edges, reverse=reverse, missing=missing)


def why(graph: Graph, target: str, *, limit: int = 25) -> list[list[str]]:
    """Every dependency path from a root to `target`, shortest first.

    Breadth-first over the reverse graph, so the first path found for each root
    is the shortest one. Visited-set per search prevents cycles from looping --
    dependency cycles are legal in Python packaging and do occur.
    """
    target = normalise(target)
    if target not in graph.reverse:
        return []

    paths: list[list[str]] = []
    queue: deque[list[str]] = deque([[target]])
    seen: set[tuple[str, ...]] = set()

    while queue and len(paths) < limit:
        path = queue.popleft()
        head = path[0]
        requirers = graph.reverse.get(head, [])
        if not requirers:
            paths.append(path)
            continue
        for requirer in requirers:
            if requirer in path:  # cycle
                continue
            candidate = [requirer, *path]
            key = tuple(candidate)
            if key in seen:
                continue
            seen.add(key)
            queue.append(candidate)

    paths.sort(key=lambda p: (len(p), p))
    return paths


def blast_radius(graph: Graph, target: str) -> set[str]:
    """Everything that would be affected if `target` were compromised."""
    target = normalise(target)
    if target not in graph.reverse:
        return set()
    affected: set[str] = set()
    queue = deque([target])
    while queue:
        current = queue.popleft()
        for requirer in graph.reverse.get(current, []):
            if requirer not in affected:
                affected.add(requirer)
                queue.append(requirer)
    return affected
