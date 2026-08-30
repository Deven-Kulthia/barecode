"""Verify installed files against the hashes the installer recorded.

Every wheel install writes a ``RECORD`` file: a CSV of
``path,sha256=<urlsafe-b64>,size`` covering every file it placed on disk.

Nothing re-checks it. ``pip check`` validates dependency *metadata*
consistency. ``pip install --require-hashes`` verifies the downloaded archive
at install time and then never looks again. There is no ``pip verify``. So if a
file inside site-packages is altered after installation -- by a poisoned
post-install step, a stray patch, a sync tool, or an attacker with write access
to the environment -- nothing in the standard toolchain notices.

That is the gap this module closes.

Normally: ``packaging`` + a hand-rolled hash loop, or nothing at all.
Instead:   ``csv`` for RECORD, ``hashlib.file_digest`` for streaming digests,
           ``base64.urlsafe_b64encode`` for the wheel hash encoding,
           ``concurrent.futures`` to parallelise the I/O-bound hashing.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .env import Environment, Package


class Verdict(StrEnum):
    OK = "ok"
    MODIFIED = "modified"
    MISSING = "missing"
    SIZE_MISMATCH = "size-mismatch"
    ESCAPES = "escapes-environment"
    UNREADABLE = "unreadable"


SEVERITY = {
    Verdict.MODIFIED: "critical",
    Verdict.SIZE_MISMATCH: "critical",
    Verdict.ESCAPES: "critical",
    Verdict.MISSING: "warning",
    Verdict.UNREADABLE: "warning",
}


@dataclass(slots=True, frozen=True)
class FileFinding:
    package: str
    path: str
    verdict: Verdict
    detail: str = ""

    @property
    def severity(self) -> str:
        return SEVERITY.get(self.verdict, "info")


@dataclass(slots=True)
class PackageResult:
    package: str
    version: str
    checked: int = 0
    unhashed: int = 0
    findings: tuple[FileFinding, ...] = ()
    skipped_reason: str = ""

    @property
    def ok(self) -> bool:
        return not self.findings and not self.skipped_reason


def _wheel_hash(data_digest: bytes) -> str:
    """Encode a raw digest the way wheels do: urlsafe base64, padding stripped."""
    return base64.urlsafe_b64encode(data_digest).rstrip(b"=").decode("ascii")


def _parse_record(record: Path) -> list[tuple[str, str, str]]:
    """Rows of (path, hash, size) from a RECORD file.

    RECORD is real CSV -- paths containing commas are quoted -- so the csv
    module is the correct reader, not a `split(",")`.
    """
    with record.open("r", encoding="utf-8", newline="") as fh:
        rows = []
        for row in csv.reader(fh):
            if not row:
                continue
            path = row[0]
            digest = row[1] if len(row) > 1 else ""
            size = row[2] if len(row) > 2 else ""
            rows.append((path, digest, size))
        return rows


def verify_package(pkg: Package, site_packages: Path, boundary: Path | None = None) -> PackageResult:
    """Re-hash every file `pkg` recorded at install time.

    `site_packages` is what RECORD paths are relative to. `boundary` is the
    outermost directory a recorded file may legitimately live in -- normally the
    environment root, because console-script entries are recorded as
    `../../../bin/foo`. A path escaping the boundary is a real finding.
    """
    boundary = (boundary or site_packages).resolve()
    result = PackageResult(package=pkg.name, version=pkg.version)
    if not pkg.record.exists():
        result.skipped_reason = "no RECORD file"
        return result

    try:
        rows = _parse_record(pkg.record)
    except (OSError, csv.Error, UnicodeDecodeError) as exc:
        result.skipped_reason = f"unreadable RECORD: {exc}"
        return result

    findings: list[FileFinding] = []
    for rel, digest, size in rows:
        # RECORD lists itself with no hash, and .pyc files are frequently
        # unhashed. An unhashed entry is not a finding -- there is nothing to
        # compare against -- but we count them so the report is honest about
        # what fraction of the install is actually covered.
        if not digest.startswith("sha256="):
            result.unhashed += 1
            continue

        target = (site_packages / rel).resolve()
        # Containment check: a malicious RECORD could carry `../../../../etc/passwd`.
        # Console scripts legitimately sit outside site-packages but inside the
        # environment root, so the boundary is the root, not site-packages.
        try:
            target.relative_to(boundary)
        except ValueError:
            findings.append(
                FileFinding(pkg.name, rel, Verdict.ESCAPES, f"recorded path resolves outside {boundary}")
            )
            continue

        try:
            stat = target.stat()
        except FileNotFoundError:
            findings.append(FileFinding(pkg.name, rel, Verdict.MISSING))
            continue
        except OSError as exc:
            findings.append(FileFinding(pkg.name, rel, Verdict.UNREADABLE, str(exc)))
            continue

        if size and str(stat.st_size) != size:
            findings.append(
                FileFinding(pkg.name, rel, Verdict.SIZE_MISMATCH, f"recorded {size} bytes, found {stat.st_size}")
            )
            continue

        try:
            with target.open("rb") as fh:
                actual = _wheel_hash(hashlib.file_digest(fh, "sha256").digest())
        except OSError as exc:
            findings.append(FileFinding(pkg.name, rel, Verdict.UNREADABLE, str(exc)))
            continue

        result.checked += 1
        if actual != digest.removeprefix("sha256="):
            findings.append(
                FileFinding(pkg.name, rel, Verdict.MODIFIED, "content differs from the hash recorded at install")
            )

    result.findings = tuple(findings)
    return result


def verify(env: Environment, *, only: str | None = None, workers: int | None = None) -> list[PackageResult]:
    """Verify every package in `env`, or just one when `only` is given.

    Hashing is I/O bound, so threads help even under the GIL: `file_digest`
    releases it while reading. Worker count follows the machine rather than a
    magic number.
    """
    targets = [p for p in env.packages.values() if only is None or p.name == only]
    if not targets:
        return []

    workers = workers or min(32, (os.process_cpu_count() or 4) * 2)
    boundary = env.boundary
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda p: verify_package(p, env.site_packages, boundary), targets))
