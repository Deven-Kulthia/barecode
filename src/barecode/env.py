"""Discover what is actually installed, by reading what the installer left behind.

Normally: ``importlib.metadata`` is stdlib and would do some of this, but it
resolves against the *running* interpreter. We need to audit an arbitrary
target environment without importing anything from it, so we read the on-disk
``.dist-info`` layout directly.

Normally: ``packaging`` (name normalisation, requirement parsing).
Instead:   ``re`` for PEP 503 normalisation, ``email.parser`` for METADATA --
           which is genuinely RFC 822, so the stdlib email parser is the
           correct tool rather than a substitute.

Nothing here executes, imports, or launches anything from the target
environment. It is all file reads. That keeps us on the right side of the
hackathon's rule against invoking separately installed tools: we parse files
pip/uv/poetry already produced, and degrade gracefully when they are absent.
"""

from __future__ import annotations

import csv
import json
import re
import sysconfig
from dataclasses import dataclass, field
from email.parser import BytesParser
from pathlib import Path

_NORMALISE = re.compile(r"[-_.]+")


def normalise(name: str) -> str:
    """PEP 503 name normalisation. `Foo.Bar_baz` -> `foo-bar-baz`."""
    return _NORMALISE.sub("-", name).strip().lower()


@dataclass(slots=True)
class Package:
    name: str  # PEP 503 normalised
    raw_name: str  # as written in METADATA
    version: str
    dist_info: Path
    installer: str | None = None
    requires: tuple[str, ...] = ()
    summary: str = ""
    licence: str = ""
    direct_url: dict | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def record(self) -> Path:
        return self.dist_info / "RECORD"

    @property
    def from_vcs(self) -> bool:
        """Installed from a git/hg URL or local path rather than an index."""
        return bool(self.direct_url and ("vcs_info" in self.direct_url or self.direct_url.get("url", "").startswith("file:")))


@dataclass(slots=True)
class PthFile:
    """A .pth file in site-packages.

    Lines beginning `import ` in a .pth file are executed by `site` on every
    single interpreter startup. It is Python's equivalent of an npm postinstall
    hook and almost nobody audits it, so we surface it explicitly.
    """

    path: Path
    import_lines: tuple[str, ...]


@dataclass(slots=True)
class Environment:
    site_packages: Path
    packages: dict[str, Package]
    root: Path | None = None
    pth_files: tuple[PthFile, ...] = ()
    problems: list[str] = field(default_factory=list)

    def get(self, name: str) -> Package | None:
        return self.packages.get(normalise(name))

    @property
    def boundary(self) -> Path:
        """Outermost directory a legitimately installed file may live in.

        RECORD paths are relative to site-packages, but console scripts are
        recorded as `../../../bin/foo` -- they land in the environment's `bin/`,
        which is entirely normal. So the containment check for detecting a
        malicious RECORD must be the environment root, not site-packages.
        """
        return self.root or self.site_packages


def environment_root(site_packages: Path) -> Path:
    """Walk up from site-packages to the venv / prefix root."""
    for parent in site_packages.parents:
        if (parent / "pyvenv.cfg").exists():
            return parent
        if (parent / "lib").is_dir() and ((parent / "bin").is_dir() or (parent / "Scripts").is_dir()):
            return parent
    parents = site_packages.parents
    return parents[2] if len(parents) >= 3 else site_packages


def find_site_packages(target: Path) -> Path | None:
    """Resolve a user-supplied path to a site-packages directory.

    Accepts, in order: a site-packages dir itself, a virtualenv root, a project
    directory containing a conventional venv, or a `pyvenv.cfg` sibling.
    Returns None if nothing convincing is found -- callers fall back to the
    running interpreter and say so.
    """
    target = target.expanduser().resolve()
    if not target.exists():
        return None

    if _looks_like_site_packages(target):
        return target

    # virtualenv root: <root>/lib/python3.X/site-packages, or Windows Lib/
    for pattern in ("lib/python*/site-packages", "Lib/site-packages"):
        for candidate in sorted(target.glob(pattern)):
            if candidate.is_dir():
                return candidate

    # project directory containing a conventional venv
    for venv_name in (".venv", "venv", "env", ".env"):
        root = target / venv_name
        if (root / "pyvenv.cfg").exists():
            found = find_site_packages(root)
            if found:
                return found
    return None


def _looks_like_site_packages(path: Path) -> bool:
    try:
        return any(True for _ in path.glob("*.dist-info"))
    except OSError:
        return False


def current_site_packages() -> Path:
    return Path(sysconfig.get_paths()["purelib"])


def scan(site_packages: Path) -> Environment:
    """Read every .dist-info directory under `site_packages`."""
    env = Environment(site_packages=site_packages, packages={}, root=environment_root(site_packages))
    try:
        entries = sorted(site_packages.iterdir())
    except OSError as exc:
        env.problems.append(f"cannot read {site_packages}: {exc}")
        return env

    pths: list[PthFile] = []
    for entry in entries:
        if entry.is_dir() and entry.name.endswith(".dist-info"):
            pkg = _read_dist_info(entry)
            if pkg is not None:
                env.packages[pkg.name] = pkg
        elif entry.suffix == ".pth":
            lines = _pth_import_lines(entry)
            if lines:
                pths.append(PthFile(path=entry, import_lines=lines))

    env.pth_files = tuple(pths)
    return env


def _header(msg, *names: str) -> str:
    """First present header among `names`, as a plain single-line string.

    `email`'s default compat32 policy hands back a `Header` object rather than a
    `str` when a header is RFC 2047-encoded or malformed -- and real METADATA
    files in the wild contain both. Some packages also inline an entire licence
    text into the `License` field, so we collapse newlines rather than letting a
    3 KB blob into a report column.
    """
    for name in names:
        value = msg.get(name)
        if value is not None:
            return " ".join(str(value).split())
    return ""


def _licence(value: str) -> str:
    """Reduce a License header to something usable as a grouping key.

    `License-Expression` (PEP 639) is a clean SPDX identifier. The older
    free-text `License` field is not: packages legitimately inline an entire
    licence document, or an ASCII-art banner, into it. Truncating that to 64
    characters yields a nonsense group name, so anything that clearly is not an
    identifier gets bucketed rather than displayed.
    """
    if not value:
        return ""
    if len(value) > 40 or "====" in value or value.count(" ") > 6:
        return "(unstructured text)"
    return value


def _read_dist_info(dist_info: Path) -> Package | None:
    metadata = dist_info / "METADATA"
    if not metadata.exists():
        return None
    try:
        with metadata.open("rb") as fh:
            msg = BytesParser().parse(fh)
    except OSError:
        return None

    raw_name = _header(msg, "Name") or dist_info.name.split("-")[0]
    pkg = Package(
        name=normalise(raw_name),
        raw_name=raw_name,
        version=_header(msg, "Version") or "0",
        dist_info=dist_info,
        requires=tuple(" ".join(str(v).split()) for v in msg.get_all("Requires-Dist") or ()),
        summary=_header(msg, "Summary"),
        licence=_licence(_header(msg, "License-Expression", "License")),
    )

    installer = dist_info / "INSTALLER"
    if installer.exists():
        try:
            pkg.installer = installer.read_text(encoding="utf-8").strip() or None
        except OSError:
            pass

    direct = dist_info / "direct_url.json"
    if direct.exists():
        try:
            pkg.direct_url = json.loads(direct.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            pkg.problems.append(f"unreadable direct_url.json: {exc}")

    if not pkg.record.exists():
        pkg.problems.append("no RECORD file -- installed files cannot be verified")

    return pkg


def _pth_import_lines(path: Path) -> tuple[str, ...]:
    """Lines in a .pth file that `site` will execute at interpreter startup."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    return tuple(
        line.strip()
        for line in text.splitlines()
        if line.startswith(("import ", "import\t"))
    )


def top_level_modules(pkg: Package) -> set[str]:
    """Import names a distribution actually provides.

    The mapping from import name to distribution name is not derivable from the
    name itself -- `import yaml` comes from `pyyaml`, `import cv2` from
    `opencv-python`. Rather than carry a hardcoded alias table that would be
    permanently out of date, we derive it from the installed layout:

      * `top_level.txt`, when the installer wrote one; otherwise
      * the first path segment of every RECORD entry, which is the package
        directory or module file the distribution installed.

    This is exact for the environment in front of us, which is the only
    environment we make claims about.
    """
    explicit = pkg.dist_info / "top_level.txt"
    if explicit.exists():
        try:
            names = {ln.strip() for ln in explicit.read_text(encoding="utf-8").splitlines() if ln.strip()}
            if names:
                return names
        except OSError:
            pass

    if not pkg.record.exists():
        return set()
    modules: set[str] = set()
    try:
        with pkg.record.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.reader(fh):
                if not row:
                    continue
                head = row[0].split("/")[0]
                if head.startswith("..") or head.endswith((".dist-info", ".data")):
                    continue
                if head.endswith(".py"):
                    modules.add(head[:-3])
                elif "." not in head:
                    modules.add(head)
    except (OSError, csv.Error, UnicodeDecodeError):
        return set()
    return modules


def provides_map(env: Environment) -> dict[str, str]:
    """import name -> distribution name, for everything installed."""
    mapping: dict[str, str] = {}
    for pkg in env.packages.values():
        for module in top_level_modules(pkg):
            mapping.setdefault(module, pkg.name)
    return mapping
