"""Hardening tests — edge cases, bad input, and error-path coverage.

No network access is used in any of these tests.
"""
from __future__ import annotations

import json

from dastlite import scan_response, scan_targets
from dastlite.core import fetch
from dastlite.cli import main


# ---------------------------------------------------------------------------
# fetch() — URL validation (no network)
# ---------------------------------------------------------------------------

class TestFetchUrlValidation:
    """fetch() must reject bad URLs and return a Target with error set."""

    def test_empty_url_returns_error(self):
        t = fetch("")
        assert t.error is not None
        assert "invalid URL" in t.error.lower() or "non-empty" in t.error.lower()
        assert t.status == 0

    def test_whitespace_only_url_returns_error(self):
        t = fetch("   ")
        assert t.error is not None

    def test_missing_scheme_returns_error(self):
        t = fetch("example.com/path")
        assert t.error is not None
        assert "scheme" in t.error.lower() or "invalid" in t.error.lower()

    def test_ftp_scheme_rejected(self):
        t = fetch("ftp://example.com/file.txt")
        assert t.error is not None
        assert "ftp" in t.error.lower() or "scheme" in t.error.lower()

    def test_file_scheme_rejected(self):
        t = fetch("file:///etc/passwd")
        assert t.error is not None

    def test_javascript_scheme_rejected(self):
        t = fetch("javascript:alert(1)")
        assert t.error is not None


# ---------------------------------------------------------------------------
# scan_targets() — edge cases around iteration
# ---------------------------------------------------------------------------

class TestScanTargetsEdgeCases:
    """scan_targets() must not crash on degenerate input."""

    def test_empty_list_returns_empty_result(self):
        result = scan_targets([])
        assert result.targets == []
        assert result.findings == []

    def test_all_blank_and_comment_lines(self):
        result = scan_targets(["", "  ", "# just a comment", "\t"])
        assert result.targets == []
        assert result.findings == []

    def test_invalid_url_scheme_captured_as_error(self):
        """fetch() returns a Target with error; run_passive_checks emits request-failed."""
        result = scan_targets(["ftp://not-valid.example"])
        # The URL with bad scheme is still recorded as a target.
        assert len(result.targets) == 1
        # A request-failed finding should be emitted.
        assert any(f.rule_id == "request-failed" for f in result.findings)


# ---------------------------------------------------------------------------
# scan_response() — None / missing headers guard
# ---------------------------------------------------------------------------

class TestScanResponseGuards:
    def test_none_headers_does_not_crash(self):
        # Must not raise; should return findings treating all headers as absent.
        findings = scan_response("https://example.com", 200, None)  # type: ignore[arg-type]
        assert isinstance(findings, list)
        # Missing security headers should be flagged.
        rule_ids = {f.rule_id for f in findings}
        assert "missing-csp" in rule_ids

    def test_empty_body_is_handled(self):
        findings = scan_response("https://example.com", 200, {}, "")
        assert isinstance(findings, list)

    def test_zero_division_free_for_zero_status(self):
        """Status 0 (fetch error) should not cause ZeroDivisionError."""
        findings = scan_response("https://example.com", 0, {})
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# CLI — timeout validation and missing-file exit code
# ---------------------------------------------------------------------------

class TestCliValidation:
    def test_negative_timeout_returns_2(self, capsys):
        rc = main(["scan", "https://example.com", "--timeout", "-1"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "timeout" in err.lower()

    def test_zero_timeout_returns_2(self, capsys):
        rc = main(["scan", "https://example.com", "--timeout", "0"])
        assert rc == 2

    def test_missing_targets_file_returns_2(self, tmp_path, capsys):
        missing = str(tmp_path / "does_not_exist.txt")
        rc = main(["scan", "--targets", missing])
        assert rc == 2
        err = capsys.readouterr().err
        assert "targets file" in err.lower() or "error" in err.lower()

    def test_empty_targets_file_returns_2(self, tmp_path, capsys):
        targets = tmp_path / "empty.txt"
        targets.write_text("# only comments\n\n", encoding="utf-8")
        rc = main(["scan", "--targets", str(targets)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "no targets" in err.lower()

    def test_no_command_returns_0_and_prints_help(self, capsys):
        rc = main([])
        assert rc == 0

    def test_sarif_output_to_file(self, tmp_path):
        """Writing SARIF to a file must succeed and produce valid JSON."""
        targets = tmp_path / "urls.txt"
        # Use a URL with bad scheme so no real fetch happens.
        targets.write_text("ftp://not-real.example\n", encoding="utf-8")
        out_file = tmp_path / "out.sarif"
        rc = main(["scan", "--targets", str(targets),
                   "--format", "sarif", "--output", str(out_file),
                   "--fail-on", "never"])
        assert rc == 0
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# mcp_server — import-level smoke (no MCP package required)
# ---------------------------------------------------------------------------

class TestMcpServerImport:
    def test_module_imports_cleanly(self):
        """mcp_server must import without raising (the broken 'scan' ref is fixed)."""
        import dastlite.mcp_server  # noqa: F401

    def test_serve_is_callable(self):
        """serve() must be importable as a callable; we do not call it (stdio)."""
        from dastlite.mcp_server import serve
        assert callable(serve)
