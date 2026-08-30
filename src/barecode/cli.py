"""Command-line surface.

Normally: ``click`` / ``typer``.
Instead:   ``argparse`` with subparsers -- which gives us subcommands, type
           coercion, ``choices``, auto-generated ``--help``, and (new in 3.14)
           coloured help output, none of which needed installing.

Conventions this CLI holds to:
  * reports go to stdout, diagnostics and progress go to stderr, so `--json`
    output stays pipeable even when something goes wrong;
  * exit codes are meaningful (see EXIT_* below) so CI can branch on them;
  * colour is suppressed automatically when stdout is not a TTY.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, env as envmod, integrity
from .ansi import Style

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ENV = 3
EXIT_INTERRUPTED = 130

SEVERITY_ORDER = ("info", "warning", "critical")


def build_parser() -> argparse.ArgumentParser:
    # `color` is a 3.14 argparse feature; pass it only where supported so the
    # CLI still constructs on 3.13.
    kwargs = {}
    if "color" in argparse.ArgumentParser.__init__.__code__.co_varnames:
        kwargs["color"] = True

    ap = argparse.ArgumentParser(
        prog="barecode",
        description="Offline supply-chain X-ray for Python environments.",
        epilog="Zero third-party dependencies. Run `make prove` to check that claim yourself.",
        **kwargs,
    )
    ap.add_argument("--version", action="version", version=f"barecode {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "path",
        nargs="?",
        default=".",
        help="project dir, virtualenv, or site-packages to inspect (default: the current interpreter's)",
    )
    common.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of a report")
    common.add_argument("--no-color", action="store_true", help="never emit ANSI colour (also honours NO_COLOR)")
    common.add_argument("-q", "--quiet", action="store_true", help="suppress progress notes on stderr")
    common.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default="warning",
        help="minimum severity that makes the command exit 1 (default: warning)",
    )

    subs = ap.add_subparsers(dest="command", metavar="<command>")

    subs.add_parser(
        "audit",
        parents=[common],
        help="headline report: what is installed, where it came from, what looks wrong",
        description="Summarise an environment: package count, installers, provenance, "
        "startup-code hooks, and integrity coverage.",
    )

    v = subs.add_parser(
        "verify",
        parents=[common],
        help="re-hash installed files against the installer's RECORD (detects tampering)",
        description="Recompute the SHA-256 of every installed file and compare it to the hash "
        "the installer recorded. There is no `pip verify`; this is that command.",
    )
    v.add_argument("--only", metavar="PKG", help="verify a single package instead of the whole environment")

    return ap


def resolve_environment(path_arg: str, note) -> envmod.Environment:
    site = envmod.find_site_packages(Path(path_arg))
    if site is None:
        site = envmod.current_site_packages()
        note(f"no virtualenv found at {path_arg!r}; falling back to this interpreter: {site}")
    return envmod.scan(site)


# ── commands ─────────────────────────────────────────────────────────────────


def cmd_audit(args, style: Style, note) -> int:
    env = resolve_environment(args.path, note)
    if env.problems and not env.packages:
        for problem in env.problems:
            print(f"error: {problem}", file=sys.stderr)
        return EXIT_ENV

    installers: dict[str, int] = {}
    for pkg in env.packages.values():
        installers[pkg.installer or "unknown"] = installers.get(pkg.installer or "unknown", 0) + 1

    vcs = sorted(p.name for p in env.packages.values() if p.from_vcs)
    no_record = sorted(p.name for p in env.packages.values() if not p.record.exists())

    if args.json:
        print(
            json.dumps(
                {
                    "site_packages": str(env.site_packages),
                    "packages": len(env.packages),
                    "installers": installers,
                    "installed_from_vcs_or_path": vcs,
                    "packages_without_record": no_record,
                    "pth_startup_hooks": [
                        {"file": str(p.path), "imports": list(p.import_lines)} for p in env.pth_files
                    ],
                    "problems": env.problems,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(style.head("BareCode audit"))
        print(f"  environment  : {env.site_packages}")
        print(f"  packages     : {len(env.packages)}")
        print(f"  installers   : {', '.join(f'{k}={v}' for k, v in sorted(installers.items())) or '(none)'}")

        if vcs:
            print(style.warn(f"  provenance   : {len(vcs)} package(s) not from an index (git URL or local path)"))
            for name in vcs:
                print(f"                 {name}")
        if no_record:
            print(style.warn(f"  unverifiable : {len(no_record)} package(s) have no RECORD file"))
        if env.pth_files:
            print(style.bad(f"  startup code : {len(env.pth_files)} .pth file(s) execute code at interpreter startup"))
            for pth in env.pth_files:
                print(f"                 {pth.path.name}: {pth.import_lines[0][:70]}")
        else:
            print(style.ok("  startup code : no .pth file executes code at startup"))
        for problem in env.problems:
            print(style.warn(f"  note         : {problem}"))
        print()
        print(style.faint("  next: `barecode verify` re-hashes every installed file against RECORD"))

    worst = "critical" if env.pth_files else ("warning" if (vcs or no_record) else "info")
    return EXIT_FINDINGS if SEVERITY_ORDER.index(worst) >= SEVERITY_ORDER.index(args.fail_on) else EXIT_OK


def cmd_verify(args, style: Style, note) -> int:
    env = resolve_environment(args.path, note)
    only = envmod.normalise(args.only) if args.only else None
    if only and only not in env.packages:
        print(f"error: {args.only!r} is not installed in {env.site_packages}", file=sys.stderr)
        return EXIT_ENV

    results = integrity.verify(env, only=only)
    findings = [f for r in results for f in r.findings]
    checked = sum(r.checked for r in results)
    unhashed = sum(r.unhashed for r in results)
    skipped = [r for r in results if r.skipped_reason]

    if args.json:
        print(
            json.dumps(
                {
                    "site_packages": str(env.site_packages),
                    "packages_verified": len(results) - len(skipped),
                    "files_hashed": checked,
                    "files_unhashed": unhashed,
                    "packages_skipped": {r.package: r.skipped_reason for r in skipped},
                    "findings": [
                        {
                            "package": f.package,
                            "path": f.path,
                            "verdict": str(f.verdict),
                            "severity": f.severity,
                            "detail": f.detail,
                        }
                        for f in findings
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(style.head("BareCode verify"))
        print(f"  environment  : {env.site_packages}")
        print(f"  packages     : {len(results) - len(skipped)} verified, {len(skipped)} skipped")
        print(f"  files hashed : {checked:,}  ({unhashed:,} entries carry no hash to check)")
        print()
        if not findings:
            print(style.ok("  ✓ every hashed file matches the digest recorded at install time"))
        else:
            by_pkg: dict[str, list] = {}
            for f in findings:
                by_pkg.setdefault(f.package, []).append(f)
            print(style.bad(f"  ✗ {len(findings)} finding(s) across {len(by_pkg)} package(s)"))
            for pkg, items in sorted(by_pkg.items()):
                print(f"\n  {style.head(pkg)}")
                for f in items:
                    label = style.bad(str(f.verdict)) if f.severity == "critical" else style.warn(str(f.verdict))
                    print(f"    {label}  {f.path}")
                    if f.detail:
                        print(f"      {style.faint(f.detail)}")
        if skipped and not args.quiet:
            print(style.faint(f"\n  {len(skipped)} package(s) skipped (no RECORD): they cannot be verified at all"))

    if not findings:
        return EXIT_OK
    worst = max((f.severity for f in findings), key=SEVERITY_ORDER.index)
    return EXIT_FINDINGS if SEVERITY_ORDER.index(worst) >= SEVERITY_ORDER.index(args.fail_on) else EXIT_OK


COMMANDS = {"audit": cmd_audit, "verify": cmd_verify}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    style = Style.detect(sys.stdout, force_off=args.no_color)
    note = (lambda msg: None) if args.quiet else (lambda msg: print(f"note: {msg}", file=sys.stderr))

    try:
        return COMMANDS[args.command](args, style, note)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # `barecode verify | head` should not traceback.
        return EXIT_OK


def run() -> None:
    """Process entry point: turn main()'s return value into an exit status.

    `zipapp` generates a __main__ that calls the configured callable and
    *discards its return value*, so an entry point that merely `return`s an int
    would always exit 0. Raising SystemExit here is what makes `--fail-on`
    usable from CI.
    """
    sys.exit(main())


if __name__ == "__main__":
    run()
