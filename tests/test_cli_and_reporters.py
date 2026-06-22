"""OFFLINE tests for CLI plumbing and reporters."""
import json
import os

import pytest

import dastlite
from dastlite.core import scan_targets, to_sarif, to_json, Target, ScanResult, Finding
from dastlite.cli import main, build_parser

HERE = os.path.dirname(__file__)
DEMO = os.path.join(HERE, "..", "demos", "01-basic", "sample_response.json")


def _demo():
    return json.load(open(DEMO, encoding="utf-8"))


def _result_from_demo():
    r = _demo()
    return scan_targets([r["url"]],
                        fetcher=lambda u: Target(url=u, status=r["status"],
                                                 headers=r["headers"], body=r["body"]))


# --- reporters -------------------------------------------------------------

def test_sarif_rules_include_synthetic():
    sarif = to_sarif(_result_from_demo())
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "xst-trace" in rule_ids
    assert "exposed-dotenv" in rule_ids
    assert "skipped-out-of-scope" in rule_ids


def test_sarif_results_match_findings():
    result = _result_from_demo()
    sarif = to_sarif(result)
    assert len(sarif["runs"][0]["results"]) == len(result.findings)


def test_json_counts_and_worst():
    result = _result_from_demo()
    j = to_json(result)
    c = j["summary"]["counts"]
    assert set(c) == {"error", "warning", "note"}
    assert j["summary"]["worst_level"] in ("error", "warning", "note", "none")


def test_empty_result_worst_none():
    assert ScanResult().worst_level == "none"


def test_finding_to_dict_roundtrip():
    f = Finding("r", "warning", "m", "https://x", "ev")
    d = f.to_dict()
    assert d["rule_id"] == "r" and d["evidence"] == "ev"


# --- parser ----------------------------------------------------------------

def test_parser_has_all_subcommands():
    parser = build_parser()
    # parse each subcommand without error
    parser.parse_args(["scan", "https://x"])
    parser.parse_args(["scan-input", "f.json"])
    parser.parse_args(["active", "https://x", "--authorized", "--scope", "x", "--rate-limit", "1"])


def test_scope_alias_target_allowlist():
    args = build_parser().parse_args(
        ["active", "https://x", "--authorized", "--target-allowlist", "x", "--rate-limit", "1"])
    assert args.scope == ["x"]


def test_scope_repeatable():
    args = build_parser().parse_args(
        ["active", "https://x", "--authorized", "--scope", "a", "--scope", "b", "--rate-limit", "1"])
    assert args.scope == ["a", "b"]


# --- main entrypoints ------------------------------------------------------

def test_no_command_prints_help():
    assert main([]) == 0


def test_version_flag_exits_0():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_scan_no_targets_returns_2(capsys):
    assert main(["scan"]) == 2


def test_scan_targets_file_comments(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("# header\nhttps://does-not-resolve.invalid\n\n", encoding="utf-8")
    rc = main(["scan", "--targets", str(p), "--format", "json",
               "--fail-on", "never", "--timeout", "1"])
    assert rc == 0


def test_scan_missing_targets_file_returns_2(tmp_path):
    rc = main(["scan", "--targets", str(tmp_path / "nope.txt")])
    assert rc == 2


def test_exports_present():
    for name in ("scan_input", "scan_input_file", "target_from_record",
                 "to_sarif", "to_json", "Target", "Finding"):
        assert hasattr(dastlite, name)
