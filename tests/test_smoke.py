"""Smoke tests for DASTLITE. No network access is used."""
import json
import os

import dastlite
from dastlite import (
    scan_response,
    scan_targets,
    run_passive_checks,
    to_sarif,
    to_json,
    Target,
)
from dastlite.cli import main

HERE = os.path.dirname(__file__)
DEMO = os.path.join(HERE, "..", "demos", "01-basic", "sample_response.json")


def _load_demo():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_exports():
    assert dastlite.TOOL_NAME == "dastlite"
    assert isinstance(dastlite.TOOL_VERSION, str) and dastlite.TOOL_VERSION


def test_demo_produces_findings():
    r = _load_demo()
    findings = scan_response(r["url"], r["status"], r["headers"], r["body"])
    rule_ids = {f.rule_id for f in findings}
    # Missing security headers should be detected.
    assert "missing-csp" in rule_ids
    assert "missing-x-frame-options" in rule_ids
    assert "hsts" in rule_ids
    # Cookie missing all three flags.
    assert "cookie-flags" in rule_ids
    # Verbose banner.
    assert "server-banner" in rule_ids
    # Information disclosure (AWS key + stack trace) is error-level.
    info = [f for f in findings if f.rule_id == "info-disclosure"]
    assert info, "expected information-disclosure findings"
    assert any(f.level == "error" for f in info)
    # Mixed content over http on an https page.
    assert "mixed-content" in rule_ids
    # Cacheable response that sets a cookie.
    assert "cacheable-secret" in rule_ids


def test_clean_response_has_no_findings():
    headers = {
        "Content-Type": "application/json",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }
    findings = run_passive_checks(
        Target(url="https://secure.example/api", status=200, headers=headers, body="{}")
    )
    assert findings == [], [f.message for f in findings]


def test_scan_targets_with_injected_fetcher():
    r = _load_demo()

    def fake_fetch(url):
        return Target(url=url, status=r["status"], headers=r["headers"], body=r["body"])

    result = scan_targets([r["url"], "# a comment line", ""], fetcher=fake_fetch)
    assert len(result.targets) == 1
    assert result.worst_level == "error"
    counts = result.counts()
    assert counts["error"] >= 1
    # Findings are sorted worst-first.
    assert result.findings[0].level == "error"


def test_request_failure_is_captured():
    def boom(url):
        return Target(url=url, error="Name or service not known")

    result = scan_targets(["https://does-not-resolve.invalid"], fetcher=boom)
    assert any(f.rule_id == "request-failed" for f in result.findings)


def test_sarif_shape():
    r = _load_demo()
    result = scan_targets(
        [r["url"]],
        fetcher=lambda u: Target(url=u, status=r["status"], headers=r["headers"], body=r["body"]),
    )
    sarif = to_sarif(result)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "dastlite"
    assert len(run["results"]) == len(result.findings)
    assert all("ruleId" in res and "message" in res for res in run["results"])
    # rules registry is populated
    assert run["tool"]["driver"]["rules"]


def test_json_report_shape():
    r = _load_demo()
    result = scan_targets(
        [r["url"]],
        fetcher=lambda u: Target(url=u, status=r["status"], headers=r["headers"], body=r["body"]),
    )
    j = to_json(result)
    assert j["tool"] == "dastlite"
    assert j["summary"]["findings"] == len(result.findings)
    assert j["summary"]["worst_level"] == "error"


def test_cli_json_and_exit_code(tmp_path, capsys):
    # Build a targets file pointing at nothing live; use --fail-on never to
    # exercise rendering without depending on network. Instead, we scan a
    # local-only invalid host and assert graceful failure handling.
    targets = tmp_path / "urls.txt"
    targets.write_text("https://does-not-resolve.invalid\n# comment\n", encoding="utf-8")
    rc = main(["scan", "--targets", str(targets), "--format", "json",
               "--fail-on", "never", "--timeout", "1"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["tool"] == "dastlite"
    assert rc == 0  # fail-on never


def test_cli_no_targets_returns_2(capsys):
    rc = main(["scan"])
    assert rc == 2


def test_version_flag():
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
