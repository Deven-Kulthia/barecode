"""Tests for BareCode.

Fixtures are synthesised on disk rather than installed with pip, so the suite is
hermetic, offline, and fast: it builds real .dist-info directories with real
RECORD hashes in a temp dir, then attacks them.

Run with:  make test    (stdlib unittest -- no pytest, no plugins)
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from barecode import advisor, cli, env as envmod, graph as graphmod, integrity, project as projectmod  # noqa: E402
from barecode.ansi import Style, plain_len  # noqa: E402


def wheel_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


class Fixture:
    """Builds a throwaway site-packages tree that looks like a real install."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.site = root / "lib" / "python3.14" / "site-packages"
        self.site.mkdir(parents=True)
        (root / "bin").mkdir(exist_ok=True)

    def add(
        self,
        name: str,
        version: str = "1.0.0",
        *,
        files: dict[str, bytes] | None = None,
        requires: tuple[str, ...] = (),
        installer: str | None = "pip",
        metadata_extra: str = "",
        record: bool = True,
        summary: str = "a test package",
    ) -> Path:
        dist = self.site / f"{name}-{version}.dist-info"
        dist.mkdir()
        lines = [f"Name: {name}", f"Version: {version}", f"Summary: {summary}"]
        lines += [f"Requires-Dist: {r}" for r in requires]
        if metadata_extra:
            lines.append(metadata_extra)
        (dist / "METADATA").write_text("\n".join(lines) + "\n\n", encoding="utf-8")
        if installer:
            (dist / "INSTALLER").write_text(installer + "\n", encoding="utf-8")

        rows = []
        for rel, content in (files or {}).items():
            target = self.site / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            rows.append(f"{rel},{wheel_hash(content)},{len(content)}")
        if record:
            rows.append(f"{dist.name}/RECORD,,")  # RECORD lists itself, unhashed
            (dist / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")
        return dist

    def scan(self) -> envmod.Environment:
        return envmod.scan(self.site)


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.fx = Fixture(Path(self._tmp.name))
        self.addCleanup(self._tmp.cleanup)


# ── env ──────────────────────────────────────────────────────────────────────


class TestNormalise(unittest.TestCase):
    def test_pep503(self):
        for raw, want in [
            ("Foo.Bar_baz", "foo-bar-baz"),
            ("ZOPE...interface", "zope-interface"),
            ("typing_extensions", "typing-extensions"),
            ("  Spaced  ", "spaced"),
        ]:
            self.assertEqual(envmod.normalise(raw), want)


class TestScan(TempCase):
    def test_reads_metadata_and_installer(self):
        self.fx.add("alpha", "2.1", requires=("beta>=1.0",), installer="uv")
        env = self.fx.scan()
        pkg = env.get("Alpha")
        self.assertIsNotNone(pkg)
        self.assertEqual(pkg.version, "2.1")
        self.assertEqual(pkg.installer, "uv")
        self.assertEqual(pkg.requires, ("beta>=1.0",))

    def test_missing_metadata_is_skipped_not_fatal(self):
        (self.fx.site / "ghost-1.0.dist-info").mkdir()
        self.fx.add("real")
        env = self.fx.scan()
        self.assertEqual(set(env.packages), {"real"})

    def test_rfc2047_encoded_header_does_not_crash(self):
        # email's compat32 policy returns a Header object, not str, for these.
        self.fx.add("weird", summary="=?utf-8?q?caf=C3=A9?=")
        env = self.fx.scan()
        self.assertIn("weird", env.packages)
        self.assertIsInstance(env.packages["weird"].summary, str)

    def test_multiline_license_is_collapsed(self):
        self.fx.add("verbose", metadata_extra="License: line one\n        line two")
        pkg = self.fx.scan().get("verbose")
        self.assertNotIn("\n", pkg.licence)

    def test_unreadable_site_packages_is_reported_not_raised(self):
        env = envmod.scan(Path("/nonexistent-path-for-test"))
        self.assertEqual(env.packages, {})
        self.assertTrue(env.problems)

    def test_missing_record_is_flagged(self):
        self.fx.add("norec", record=False)
        pkg = self.fx.scan().get("norec")
        self.assertTrue(any("RECORD" in p for p in pkg.problems))

    def test_pth_startup_hook_detected(self):
        # This string is inert test *data*: it is written into a .pth file and
        # only ever read back as text. BareCode never executes anything it finds
        # in a target environment -- that is the whole point of the tool.
        self.fx.add("plain")
        (self.fx.site / "evil.pth").write_text("import os; os.system('echo pwned')\n", encoding="utf-8")
        (self.fx.site / "benign.pth").write_text("../some/path\n", encoding="utf-8")
        env = self.fx.scan()
        self.assertEqual(len(env.pth_files), 1, "only the executing .pth counts")
        self.assertIn("evil.pth", str(env.pth_files[0].path))

    def test_direct_url_marks_vcs_provenance(self):
        dist = self.fx.add("fromgit")
        (dist / "direct_url.json").write_text(
            json.dumps({"url": "https://github.com/x/y", "vcs_info": {"vcs": "git"}}), encoding="utf-8"
        )
        self.assertTrue(self.fx.scan().get("fromgit").from_vcs)

    def test_environment_root_found_from_venv_layout(self):
        (self.fx.root / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
        self.assertEqual(envmod.environment_root(self.fx.site), self.fx.root)

    def test_find_site_packages_accepts_venv_root(self):
        (self.fx.root / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
        self.fx.add("x")
        # Compare resolved paths: find_site_packages resolves symlinks on
        # purpose (on macOS /var -> /private/var), and callers want the real path.
        self.assertEqual(envmod.find_site_packages(self.fx.root), self.fx.site.resolve())

    def test_find_site_packages_returns_none_for_unrelated_dir(self):
        self.assertIsNone(envmod.find_site_packages(self.fx.root / "bin"))


# ── integrity: the whole point of the tool ───────────────────────────────────


class TestIntegrity(TempCase):
    def _verify(self, name: str) -> integrity.PackageResult:
        env = self.fx.scan()
        return integrity.verify_package(env.packages[name], env.site_packages, env.boundary)

    def test_clean_install_has_no_findings(self):
        self.fx.add("clean", files={"clean/__init__.py": b"x = 1\n"})
        result = self._verify("clean")
        self.assertTrue(result.ok, result.findings)
        self.assertEqual(result.checked, 1)

    def test_appended_bytes_detected(self):
        self.fx.add("victim", files={"victim/mod.py": b"safe\n"})
        (self.fx.site / "victim/mod.py").write_bytes(b"safe\n# extra\n")
        verdicts = [f.verdict for f in self._verify("victim").findings]
        self.assertIn(integrity.Verdict.SIZE_MISMATCH, verdicts)

    def test_same_length_edit_detected_by_hash(self):
        """The attack that survives size and mtime checks."""
        self.fx.add("victim", files={"victim/mod.py": b"AUTHORISED\n"})
        (self.fx.site / "victim/mod.py").write_bytes(b"BACKDOORED\n")  # identical length
        findings = self._verify("victim").findings
        self.assertEqual([f.verdict for f in findings], [integrity.Verdict.MODIFIED])
        self.assertEqual(findings[0].severity, "critical")

    def test_deleted_file_detected(self):
        self.fx.add("gappy", files={"gappy/mod.py": b"data\n"})
        (self.fx.site / "gappy/mod.py").unlink()
        self.assertEqual([f.verdict for f in self._verify("gappy").findings], [integrity.Verdict.MISSING])

    def test_console_script_outside_site_packages_is_not_a_finding(self):
        """RECORD legitimately references ../../../bin/foo -- that is normal."""
        content = b"#!/usr/bin/env python3\n"
        (self.fx.root / "bin" / "tool").write_bytes(content)
        dist = self.fx.add("scripted", files={"scripted/__init__.py": b""})
        rel = "../../../bin/tool"
        rows = (dist / "RECORD").read_text().splitlines()
        rows.insert(0, f"{rel},{wheel_hash(content)},{len(content)}")
        (dist / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")
        result = self._verify("scripted")
        self.assertTrue(result.ok, result.findings)

    def test_record_path_escaping_the_environment_is_a_finding(self):
        dist = self.fx.add("malicious", files={"malicious/__init__.py": b""})
        (dist / "RECORD").write_text(
            f"../../../../../../etc/passwd,{wheel_hash(b'x')},1\n", encoding="utf-8"
        )
        self.assertEqual(
            [f.verdict for f in self._verify("malicious").findings], [integrity.Verdict.ESCAPES]
        )

    def test_unhashed_entries_are_counted_not_flagged(self):
        self.fx.add("partial", files={"partial/mod.py": b"data\n"})
        result = self._verify("partial")
        self.assertEqual(result.unhashed, 1)  # the RECORD self-entry
        self.assertTrue(result.ok)

    def test_quoted_csv_path_with_comma(self):
        name = "odd/file,with comma.py"
        content = b"data\n"
        dist = self.fx.add("csvy")
        target = self.fx.site / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        with (dist / "RECORD").open("w", encoding="utf-8", newline="") as fh:
            fh.write(f'"{name}",{wheel_hash(content)},{len(content)}\n')
        self.assertTrue(self._verify("csvy").ok)

    def test_missing_record_is_skipped_with_a_reason(self):
        self.fx.add("norec", record=False)
        result = self._verify("norec")
        self.assertFalse(result.ok)
        self.assertIn("RECORD", result.skipped_reason)

    def test_verify_whole_environment(self):
        self.fx.add("a", files={"a.py": b"1"})
        self.fx.add("b", files={"b.py": b"2"})
        results = integrity.verify(self.fx.scan())
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.ok for r in results))

    def test_verify_only_one_package(self):
        self.fx.add("a", files={"a.py": b"1"})
        self.fx.add("b", files={"b.py": b"2"})
        self.assertEqual(len(integrity.verify(self.fx.scan(), only="b")), 1)


# ── graph ────────────────────────────────────────────────────────────────────


class TestRequirementParsing(unittest.TestCase):
    def test_forms(self):
        cases = [
            ("requests", "requests", "", ""),
            ("requests>=2.0", "requests", ">=2.0", ""),
            ("requests[security]>=2.0", "requests", ">=2.0", ""),
            ('pytest ; extra == "dev"', "pytest", "", 'extra == "dev"'),
            ('tomli>=1.0 ; python_version < "3.11"', "tomli", ">=1.0", 'python_version < "3.11"'),
            ("Zope.Interface", "zope-interface", "", ""),
        ]
        for line, name, spec, marker in cases:
            req = graphmod.parse_requirement(line)
            self.assertIsNotNone(req, line)
            self.assertEqual(req.name, name, line)
            self.assertEqual(req.specifier, spec, line)
            self.assertEqual(req.marker, marker, line)

    def test_extras_captured(self):
        self.assertEqual(graphmod.parse_requirement("requests[security,socks]").extras, ("security", "socks"))

    def test_extra_only_marker_flagged(self):
        self.assertTrue(graphmod.parse_requirement('black ; extra == "dev"').extra_only)
        self.assertFalse(graphmod.parse_requirement('tomli ; python_version < "3.11"').extra_only)

    def test_garbage_returns_none(self):
        for bad in ("", "   ", "!!!", "=1.0"):
            self.assertIsNone(graphmod.parse_requirement(bad), bad)


class TestGraph(TempCase):
    def _chain(self):
        self.fx.add("app", requires=("mid",))
        self.fx.add("mid", requires=("leaf",))
        self.fx.add("leaf")
        return graphmod.build(self.fx.scan())

    def test_roots_are_what_you_asked_for(self):
        self.assertEqual(self._chain().roots, ["app"])

    def test_why_finds_the_full_path(self):
        self.assertEqual(graphmod.why(self._chain(), "leaf"), [["app", "mid", "leaf"]])

    def test_why_on_a_root_returns_itself(self):
        self.assertEqual(graphmod.why(self._chain(), "app"), [["app"]])

    def test_why_unknown_package_is_empty(self):
        self.assertEqual(graphmod.why(self._chain(), "nope"), [])

    def test_blast_radius(self):
        self.assertEqual(graphmod.blast_radius(self._chain(), "leaf"), {"app", "mid"})

    def test_cycle_does_not_hang(self):
        self.fx.add("a", requires=("b",))
        self.fx.add("b", requires=("a",))
        g = graphmod.build(self.fx.scan())
        self.assertIsInstance(graphmod.why(g, "a"), list)  # terminates
        self.assertEqual(graphmod.blast_radius(g, "a"), {"a", "b"})

    def test_requirement_on_uninstalled_package_is_missing_not_an_edge(self):
        self.fx.add("app", requires=("absent>=1.0",))
        g = graphmod.build(self.fx.scan())
        self.assertEqual(g.edges["app"], [])
        self.assertEqual(g.missing["app"][0].name, "absent")

    def test_multiple_paths_shortest_first(self):
        self.fx.add("top", requires=("mid", "leaf"))
        self.fx.add("mid", requires=("leaf",))
        self.fx.add("leaf")
        paths = graphmod.why(graphmod.build(self.fx.scan()), "leaf")
        self.assertEqual(paths[0], ["top", "leaf"])
        self.assertIn(["top", "mid", "leaf"], paths)


# ── advisor ──────────────────────────────────────────────────────────────────


class TestAdvisor(TempCase):
    def test_finds_replaceable_and_reports_confidence(self):
        self.fx.add("six", "1.17.0")
        self.fx.add("numpy", "2.0")
        self.fx.add("nothing-special", "1.0")
        hits = {h.swap.package: h for h in advisor.killable(self.fx.scan())}
        self.assertEqual(set(hits), {"six", "numpy"})
        self.assertEqual(hits["six"].swap.confidence, advisor.Confidence.DROP_IN)
        self.assertEqual(hits["numpy"].swap.confidence, advisor.Confidence.NONE)

    def test_transitive_hits_marked(self):
        self.fx.add("app", requires=("six",))
        self.fx.add("six")
        g = graphmod.build(self.fx.scan())
        hit = advisor.killable(self.fx.scan(), g.reverse)[0]
        self.assertFalse(hit.direct)

    def test_table_is_internally_consistent(self):
        for swap in advisor.TABLE:
            self.assertEqual(swap.package, envmod.normalise(swap.package), swap.package)
            if swap.confidence is advisor.Confidence.NONE:
                self.assertTrue(swap.note, f"{swap.package}: a NONE row must explain itself")
        self.assertEqual(len(advisor.BY_NAME), len(advisor.TABLE), "duplicate package in TABLE")


# ── ansi ─────────────────────────────────────────────────────────────────────


class TestStyle(unittest.TestCase):
    def test_disabled_style_is_a_passthrough(self):
        self.assertEqual(Style(False)("hi", "red", "bold"), "hi")

    def test_enabled_style_wraps_and_resets(self):
        out = Style(True)("hi", "red")
        self.assertTrue(out.startswith("\x1b[31m") and out.endswith("\x1b[0m"))

    def test_no_color_env_wins(self):
        import os

        os.environ["NO_COLOR"] = ""  # presence matters, not value
        self.addCleanup(os.environ.pop, "NO_COLOR", None)
        self.assertFalse(Style.detect(io.StringIO()).enabled)

    def test_non_tty_gets_no_colour(self):
        self.assertFalse(Style.detect(io.StringIO()).enabled)

    def test_plain_len_ignores_escapes(self):
        self.assertEqual(plain_len(Style(True)("abc", "red", "bold")), 3)


# ── CLI: exit codes and stream discipline ────────────────────────────────────


class TestCLI(TempCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_no_command_prints_help_and_exits_usage(self):
        code, out, _ = self.run_cli()
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("barecode", out)

    def test_unknown_package_exits_env_error(self):
        self.fx.add("present")
        code, _, err = self.run_cli("why", "absent", "-p", str(self.fx.site), "-q")
        self.assertEqual(code, cli.EXIT_ENV)
        self.assertIn("not installed", err)

    def test_clean_verify_exits_zero(self):
        self.fx.add("clean", files={"clean.py": b"ok\n"})
        code, out, _ = self.run_cli("verify", "-p", str(self.fx.site), "-q")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("matches", out)

    def test_tampered_verify_exits_one(self):
        self.fx.add("victim", files={"victim.py": b"AUTHORISED\n"})
        (self.fx.site / "victim.py").write_bytes(b"BACKDOORED\n")
        code, out, _ = self.run_cli("verify", "-p", str(self.fx.site), "-q")
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("modified", out)

    def test_fail_on_critical_ignores_warnings(self):
        self.fx.add("gappy", files={"gappy.py": b"data\n"})
        (self.fx.site / "gappy.py").unlink()  # MISSING == warning
        code, _, _ = self.run_cli("verify", "-p", str(self.fx.site), "-q", "--fail-on", "critical")
        self.assertEqual(code, cli.EXIT_OK)
        code, _, _ = self.run_cli("verify", "-p", str(self.fx.site), "-q", "--fail-on", "warning")
        self.assertEqual(code, cli.EXIT_FINDINGS)

    def test_json_output_is_valid_json_on_every_command(self):
        self.fx.add("app", requires=("six",), files={"app.py": b"x\n"})
        self.fx.add("six", files={"six.py": b"y\n"})
        for argv in (
            ("audit", "-p", str(self.fx.site), "-q", "--json"),
            ("verify", "-p", str(self.fx.site), "-q", "--json"),
            ("why", "six", "-p", str(self.fx.site), "-q", "--json"),
            ("killable", "-p", str(self.fx.site), "-q", "--json"),
        ):
            _, out, _ = self.run_cli(*argv)
            json.loads(out)  # raises if malformed

    def test_json_output_carries_no_ansi_escapes(self):
        self.fx.add("six", files={"six.py": b"y\n"})
        _, out, _ = self.run_cli("killable", "-p", str(self.fx.site), "-q", "--json")
        self.assertNotIn("\x1b", out)

    def test_notes_go_to_stderr_not_stdout(self):
        self.fx.add("x", files={"x.py": b"1\n"})
        _, out, err = self.run_cli("audit", "-p", "/nonexistent-dir-xyz", "--json")
        json.loads(out)  # stdout stayed machine-readable
        self.assertIn("note:", err)

    def test_quiet_suppresses_notes(self):
        _, _, err = self.run_cli("audit", "-p", "/nonexistent-dir-xyz", "-q", "--json")
        self.assertEqual(err, "")

    def test_pth_hook_makes_audit_fail(self):
        self.fx.add("x")
        (self.fx.site / "hook.pth").write_text("import evil\n", encoding="utf-8")
        code, out, _ = self.run_cli("audit", "-p", str(self.fx.site), "-q")
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("startup", out)

    def test_help_lists_every_command(self):
        parser = cli.build_parser()
        text = parser.format_help()
        for command in cli.COMMANDS:
            self.assertIn(command, text)


# ── project: declared vs installed vs imported ───────────────────────────────


class TestDeclared(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.proj = Path(self._tmp.name) / "proj"
        self.proj.mkdir()

    def write(self, name: str, text: str) -> None:
        (self.proj / name).write_text(text, encoding="utf-8")

    def test_pep621_dependencies_and_extras(self):
        self.write(
            "pyproject.toml",
            '[project]\nname="x"\nversion="1"\n'
            'dependencies=["requests>=2","Flask"]\n'
            '[project.optional-dependencies]\ndev=["pytest"]\n',
        )
        dec = projectmod.declared_dependencies(self.proj)
        self.assertEqual(dec.names, {"requests", "flask", "pytest"})
        self.assertEqual(dec.sources, ["pyproject.toml"])

    def test_poetry_tables_including_groups(self):
        self.write(
            "pyproject.toml",
            "[tool.poetry.dependencies]\npython='^3.12'\nrequests='*'\n"
            "[tool.poetry.group.dev.dependencies]\nblack='*'\n",
        )
        dec = projectmod.declared_dependencies(self.proj)
        self.assertEqual(dec.names, {"requests", "black"})
        self.assertNotIn("python", dec.names)

    def test_requirements_txt_forms(self):
        self.write(
            "requirements.txt",
            "# a comment\n\nrequests==2.31.0\n"
            "Flask ; python_version > '3.8'\n"
            "--index-url https://example.invalid/simple\n"
            "-e .\n"
            "urllib3  # trailing comment\n",
        )
        dec = projectmod.declared_dependencies(self.proj)
        self.assertEqual(dec.names, {"requests", "flask", "urllib3"})

    def test_requirements_include_is_followed(self):
        self.write("requirements.txt", "-r base.txt\nrequests\n")
        self.write("base.txt", "flask\n")
        self.assertEqual(projectmod.declared_dependencies(self.proj).names, {"requests", "flask"})

    def test_requirements_include_cycle_terminates(self):
        self.write("requirements.txt", "-r other.txt\nrequests\n")
        self.write("other.txt", "-r requirements.txt\nflask\n")
        self.assertEqual(projectmod.declared_dependencies(self.proj).names, {"requests", "flask"})

    def test_malformed_pyproject_is_reported_not_raised(self):
        self.write("pyproject.toml", "this is not = = toml")
        dec = projectmod.declared_dependencies(self.proj)
        self.assertTrue(dec.problems)

    def test_no_manifest_yields_no_sources(self):
        self.assertEqual(projectmod.declared_dependencies(self.proj).sources, [])


class TestImports(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.proj = Path(self._tmp.name) / "proj"
        self.proj.mkdir()

    def test_ast_ignores_module_names_in_strings_and_comments(self):
        (self.proj / "a.py").write_text(
            'import requests\n'
            '# import evil_from_comment\n'
            's = "import evil_from_string"\n',
            encoding="utf-8",
        )
        found = projectmod.imported_modules(self.proj)
        self.assertIn("requests", found)
        self.assertNotIn("evil_from_comment", found)
        self.assertNotIn("evil_from_string", found)

    def test_relative_imports_skipped(self):
        (self.proj / "a.py").write_text("from . import sibling\nfrom .mod import thing\n", encoding="utf-8")
        self.assertEqual(projectmod.imported_modules(self.proj), {})

    def test_dotted_import_reduced_to_top_level(self):
        (self.proj / "a.py").write_text("import os.path\nfrom xml.etree import ElementTree\n", encoding="utf-8")
        self.assertEqual(set(projectmod.imported_modules(self.proj)), {"os", "xml"})

    def test_venv_and_cache_dirs_skipped(self):
        for skip in (".venv", "__pycache__", "node_modules"):
            d = self.proj / skip
            d.mkdir()
            (d / "junk.py").write_text("import should_not_be_seen\n", encoding="utf-8")
        (self.proj / "real.py").write_text("import requests\n", encoding="utf-8")
        self.assertEqual(set(projectmod.imported_modules(self.proj)), {"requests"})

    def test_syntax_error_in_project_file_is_skipped_not_fatal(self):
        (self.proj / "broken.py").write_text("def (((\n", encoding="utf-8")
        (self.proj / "fine.py").write_text("import requests\n", encoding="utf-8")
        self.assertEqual(set(projectmod.imported_modules(self.proj)), {"requests"})

    def test_first_party_names_from_root_and_src(self):
        (self.proj / "mymod.py").write_text("", encoding="utf-8")
        pkg = self.proj / "src" / "mypkg"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        self.assertEqual(projectmod.first_party_names(self.proj), {"mymod", "mypkg"})


class TestDepAnalysis(TempCase):
    """The three-set comparison, with a synthetic environment."""

    def setUp(self) -> None:
        super().setUp()
        self.proj = Path(self._tmp.name) / "proj"
        self.proj.mkdir()

    def build(self, declared: str, source: str):
        (self.proj / "pyproject.toml").write_text(
            f'[project]\nname="x"\nversion="1"\ndependencies=[{declared}]\n', encoding="utf-8"
        )
        (self.proj / "app.py").write_text(source, encoding="utf-8")
        env = self.fx.scan()
        g = graphmod.build(env)
        return projectmod.analyse(self.proj, envmod.provides_map(env), set(env.packages), g.edges)

    def test_clean_project(self):
        self.fx.add("requests", files={"requests/__init__.py": b""})
        report = self.build('"requests"', "import requests\nimport json\n")
        self.assertTrue(report.clean, (report.unused, report.missing, report.phantom))
        self.assertEqual(report.stdlib_used, ["json"])

    def test_unused_declaration_detected(self):
        self.fx.add("requests", files={"requests/__init__.py": b""})
        self.fx.add("rich", files={"rich/__init__.py": b""})
        report = self.build('"requests","rich"', "import requests\n")
        self.assertEqual(report.unused, ["rich"])

    def test_missing_import_detected(self):
        report = self.build('""', "import totally_absent\n")
        self.assertIn("totally_absent", report.missing)
        self.assertEqual(report.missing["totally_absent"], ["app.py"])

    def test_transitive_dependency_is_not_phantom(self):
        """The false positive that would make this command untrustworthy."""
        self.fx.add("requests", requires=("certifi",), files={"requests/__init__.py": b""})
        self.fx.add("certifi", files={"certifi/__init__.py": b""})
        report = self.build('"requests"', "import requests\n")
        self.assertEqual(report.phantom, [], "certifi is a legitimate transitive dep")

    def test_genuinely_undeclared_package_is_phantom(self):
        self.fx.add("requests", files={"requests/__init__.py": b""})
        self.fx.add("pyjokes", files={"pyjokes/__init__.py": b""})
        report = self.build('"requests"', "import requests\n")
        self.assertEqual(report.phantom, ["pyjokes"])

    def test_bootstrap_packages_are_never_phantom(self):
        self.fx.add("requests", files={"requests/__init__.py": b""})
        for name in ("pip", "setuptools", "wheel"):
            self.fx.add(name, files={f"{name}/__init__.py": b""})
        report = self.build('"requests"', "import requests\n")
        self.assertEqual(report.phantom, [])

    def test_no_declaration_means_no_phantom_claims(self):
        self.fx.add("anything", files={"anything/__init__.py": b""})
        (self.proj / "app.py").write_text("import json\n", encoding="utf-8")
        env = self.fx.scan()
        report = projectmod.analyse(self.proj, envmod.provides_map(env), set(env.packages), {})
        self.assertEqual(report.phantom, [])

    def test_import_name_differing_from_distribution_name(self):
        """`import yaml` must resolve to the `pyyaml` distribution."""
        self.fx.add("pyyaml", files={"yaml/__init__.py": b""})
        report = self.build('"pyyaml"', "import yaml\n")
        self.assertTrue(report.clean, (report.unused, report.missing, report.phantom))

    def test_top_level_txt_is_preferred_when_present(self):
        dist = self.fx.add("weird", files={"actual_module/__init__.py": b""})
        (dist / "top_level.txt").write_text("declared_name\n", encoding="utf-8")
        pkg = self.fx.scan().get("weird")
        self.assertEqual(envmod.top_level_modules(pkg), {"declared_name"})

    def test_provides_map_derived_from_record(self):
        self.fx.add("pyyaml", files={"yaml/__init__.py": b"", "yaml/parser.py": b""})
        self.assertEqual(envmod.provides_map(self.fx.scan()).get("yaml"), "pyyaml")


class TestDepsCLI(TempCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_missing_import_exits_one_and_json_is_valid(self):
        proj = Path(self._tmp.name) / "proj"
        proj.mkdir()
        (proj / "pyproject.toml").write_text(
            '[project]\nname="x"\nversion="1"\ndependencies=["absent-dist"]\n', encoding="utf-8"
        )
        (proj / "app.py").write_text("import absent_module\n", encoding="utf-8")
        code, out, _ = self.run_cli("deps", "-p", str(self.fx.site), "--project", str(proj), "-q", "--json")
        self.assertEqual(code, cli.EXIT_FINDINGS)
        payload = json.loads(out)
        self.assertIn("absent_module", payload["missing"])

    def test_nonexistent_project_dir_exits_env_error(self):
        code, _, err = self.run_cli("deps", "--project", "/no/such/dir", "-q")
        self.assertEqual(code, cli.EXIT_ENV)
        self.assertIn("not a directory", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
