"""OFFLINE tests for the passive scan-input mode (file / HAR / records)."""
import json
import os

import pytest

from dastlite.core import (
    scan_input, scan_input_file, target_from_record, _iter_records,
    to_json, to_sarif,
)
from dastlite.cli import main

HERE = os.path.dirname(__file__)
CAP = os.path.join(HERE, "..", "demos", "04-capture", "captures.json")
HAR = os.path.join(HERE, "..", "demos", "04-capture", "sample.har")


def test_target_from_record_dict_headers():
    t = target_from_record({"url": "https://x/", "status": 200,
                            "headers": {"Server": "nginx"}, "body": "hi"})
    assert t.url == "https://x/" and t.status == 200
    assert t.header("server") == "nginx" and t.body == "hi"


def test_target_from_record_list_headers_name_value():
    t = target_from_record({"url": "https://x/", "status": 200,
                            "headers": [{"name": "Server", "value": "nginx"}]})
    assert t.header("server") == "nginx"


def test_target_from_record_list_headers_pairs():
    t = target_from_record({"url": "https://x/", "headers": [["Server", "nginx"]]})
    assert t.header("server") == "nginx"


def test_target_from_record_defaults():
    t = target_from_record({})
    assert t.url == "" and t.status == 0 and t.body == "" and t.headers == {}


def test_iter_records_responses_key():
    assert len(_iter_records({"responses": [{"url": "a"}, {"url": "b"}]})) == 2


def test_iter_records_bare_list():
    assert len(_iter_records([{"url": "a"}])) == 1


def test_iter_records_single_dict():
    assert len(_iter_records({"url": "a", "status": 200})) == 1


def test_iter_records_har():
    recs = _iter_records(json.load(open(HAR, encoding="utf-8")))
    assert recs and recs[0]["url"].startswith("https://")


def test_scan_input_multi_record():
    data = json.load(open(CAP, encoding="utf-8"))
    result = scan_input(data)
    assert len(result.targets) == 2
    rules = {f.rule_id for f in result.findings}
    # the shop record has cors+credentials, clear-text form
    assert "cors-wildcard" in rules
    assert "clear-text-form" in rules


def test_scan_input_file_har_finds_sql_error():
    result = scan_input_file(HAR)
    rules = {f.rule_id for f in result.findings}
    assert "info-disclosure" in rules
    assert result.worst_level == "error"


def test_scan_input_clean_record_has_no_header_findings():
    data = {"responses": [{
        "url": "https://api.example/v1/data", "status": 200,
        "headers": {
            "Content-Type": "application/json",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Strict-Transport-Security": "max-age=63072000",
        }, "body": "{}"}]}
    assert scan_input(data).findings == []


def test_scan_input_skips_non_dict_entries():
    result = scan_input([{"url": "https://x/", "status": 200, "headers": {}}, "junk", 5])
    assert len(result.targets) == 1


def test_cli_scan_input_json(capsys):
    rc = main(["scan-input", CAP, "--format", "json", "--fail-on", "never"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["tool"] == "dastlite"
    assert data["summary"]["targets"] == 2
    assert rc == 0


def test_cli_scan_input_sarif(capsys):
    rc = main(["scan-input", HAR, "--format", "sarif", "--fail-on", "never"])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert rc == 0


def test_cli_scan_input_fail_on_error_exit_1(capsys):
    rc = main(["scan-input", HAR, "--format", "json", "--fail-on", "error"])
    capsys.readouterr()
    assert rc == 1  # HAR has an SQL-error info-disclosure (error level)


def test_cli_scan_input_missing_file(capsys):
    rc = main(["scan-input", os.path.join(HERE, "nope.json")])
    assert rc == 2


def test_cli_scan_input_bad_json(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    rc = main(["scan-input", str(p)])
    assert rc == 2


def test_cli_scan_input_table_output_to_file(tmp_path):
    out = tmp_path / "r.txt"
    rc = main(["scan-input", CAP, "--format", "table", "-o", str(out), "--fail-on", "never"])
    assert rc == 0
    assert "Scanned 2 target" in out.read_text(encoding="utf-8")
