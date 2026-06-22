"""Exhaustive OFFLINE unit tests for every passive check. No network."""
import pytest

from dastlite.core import (
    Target, run_passive_checks, scan_response, severity_rank,
    _check_hsts, _check_cookie_flags, _check_server_banner, _check_content_type,
    _check_cache_sensitive, _check_info_disclosure, _check_mixed_content,
    _check_cors_wildcard, _check_permissions_policy, _check_clear_text_form,
    PASSIVE_CHECKS,
)


def _rules(findings):
    return {f.rule_id for f in findings}


# --- severity ranking ------------------------------------------------------

@pytest.mark.parametrize("level,rank", [
    ("error", 3), ("warning", 2), ("note", 1), ("none", 0), ("bogus", 0),
])
def test_severity_rank(level, rank):
    assert severity_rank(level) == rank


# --- Target.header is case-insensitive ------------------------------------

def test_header_case_insensitive():
    t = Target(url="https://x", headers={"Content-Type": "text/html"})
    assert t.header("content-type") == "text/html"
    assert t.header("CONTENT-TYPE") == "text/html"
    assert t.header("missing") is None


# --- missing security headers ---------------------------------------------

def test_all_security_headers_missing_on_https():
    t = Target(url="https://x/", status=200, headers={"Content-Type": "text/html; charset=utf-8"})
    rules = _rules(run_passive_checks(t))
    for r in ("missing-csp", "missing-x-content-type-options",
              "missing-x-frame-options", "missing-referrer-policy",
              "missing-permissions-policy", "hsts"):
        assert r in rules


def test_present_security_headers_silence_checks():
    t = Target(url="https://x/", status=200, headers={
        "Content-Type": "application/json",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Strict-Transport-Security": "max-age=99999999",
    })
    assert run_passive_checks(t) == []


# --- HSTS ------------------------------------------------------------------

def test_hsts_skipped_for_http():
    assert _check_hsts(Target(url="http://x/", headers={})) == []


def test_hsts_missing_on_https():
    assert _check_hsts(Target(url="https://x/", headers={})) != []


def test_hsts_short_max_age_flagged():
    t = Target(url="https://x/", headers={"Strict-Transport-Security": "max-age=100"})
    assert _check_hsts(t) != []


def test_hsts_long_max_age_ok():
    t = Target(url="https://x/", headers={"Strict-Transport-Security": "max-age=31536000"})
    assert _check_hsts(t) == []


def test_hsts_no_max_age_flagged():
    t = Target(url="https://x/", headers={"Strict-Transport-Security": "includeSubDomains"})
    assert _check_hsts(t) != []


# --- cookie flags ----------------------------------------------------------

def test_cookie_missing_all_flags_https():
    t = Target(url="https://x/", headers={"Set-Cookie": "a=b; Path=/"})
    msgs = " ".join(m for m, _ in _check_cookie_flags(t))
    assert "HttpOnly" in msgs and "Secure" in msgs and "SameSite" in msgs


def test_cookie_secure_not_required_on_http():
    t = Target(url="http://x/", headers={"Set-Cookie": "a=b; HttpOnly; SameSite=Lax"})
    assert _check_cookie_flags(t) == []


def test_cookie_fully_flagged_https_ok():
    t = Target(url="https://x/", headers={"Set-Cookie": "a=b; HttpOnly; Secure; SameSite=Strict"})
    assert _check_cookie_flags(t) == []


def test_cookie_no_set_cookie_header():
    assert _check_cookie_flags(Target(url="https://x/", headers={})) == []


# --- server banner ---------------------------------------------------------

def test_server_banner_with_version():
    t = Target(url="https://x/", headers={"Server": "Apache/2.4.49"})
    assert _check_server_banner(t) != []


def test_server_banner_no_version_no_finding():
    t = Target(url="https://x/", headers={"Server": "cloudflare"})
    assert _check_server_banner(t) == []


def test_x_powered_by_flagged_even_without_digits():
    t = Target(url="https://x/", headers={"X-Powered-By": "PHP"})
    assert _check_server_banner(t) != []


# --- content-type ----------------------------------------------------------

def test_content_type_missing_on_2xx():
    assert _check_content_type(Target(url="https://x/", status=200, headers={})) != []


def test_content_type_present_ok():
    t = Target(url="https://x/", status=200, headers={"Content-Type": "application/json"})
    assert _check_content_type(t) == []


def test_html_without_charset_flagged():
    t = Target(url="https://x/", status=200, headers={"Content-Type": "text/html"})
    assert _check_content_type(t) != []


def test_html_with_charset_ok():
    t = Target(url="https://x/", status=200, headers={"Content-Type": "text/html; charset=utf-8"})
    assert _check_content_type(t) == []


# --- cacheable secret ------------------------------------------------------

def test_cacheable_cookie_flagged():
    t = Target(url="https://x/", headers={"Set-Cookie": "s=1", "Cache-Control": "max-age=600"})
    assert _check_cache_sensitive(t) != []


def test_cacheable_cookie_no_store_ok():
    t = Target(url="https://x/", headers={"Set-Cookie": "s=1", "Cache-Control": "no-store"})
    assert _check_cache_sensitive(t) == []


def test_cacheable_private_ok():
    t = Target(url="https://x/", headers={"Set-Cookie": "s=1", "Cache-Control": "private"})
    assert _check_cache_sensitive(t) == []


def test_no_cookie_no_cache_check():
    assert _check_cache_sensitive(Target(url="https://x/", headers={"Cache-Control": "max-age=1"})) == []


# --- info disclosure -------------------------------------------------------

@pytest.mark.parametrize("body", [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "key=AKIAIOSFODNN7EXAMPLE",
    "Traceback (most recent call last):",
    "<title>Exception</title>",
    "you have an error in your SQL syntax",
])
def test_info_disclosure_patterns(body):
    t = Target(url="https://x/", body=body)
    assert _check_info_disclosure(t) != []


def test_info_disclosure_clean_body():
    assert _check_info_disclosure(Target(url="https://x/", body="hello world")) == []


# --- mixed content ---------------------------------------------------------

def test_mixed_content_on_https():
    t = Target(url="https://x/", body='<script src="http://cdn/x.js"></script>')
    assert _check_mixed_content(t) != []


def test_mixed_content_skipped_on_http():
    t = Target(url="http://x/", body='<script src="http://cdn/x.js"></script>')
    assert _check_mixed_content(t) == []


def test_mixed_content_https_resource_ok():
    t = Target(url="https://x/", body='<script src="https://cdn/x.js"></script>')
    assert _check_mixed_content(t) == []


# --- CORS ------------------------------------------------------------------

def test_cors_wildcard_with_credentials_is_error():
    t = Target(url="https://x/", headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"})
    f = _check_cors_wildcard(t)
    assert f and "serious" in f[0][0].lower()


def test_cors_wildcard_without_credentials():
    t = Target(url="https://x/", headers={"Access-Control-Allow-Origin": "*"})
    assert _check_cors_wildcard(t) != []


def test_cors_specific_origin_ok():
    t = Target(url="https://x/", headers={"Access-Control-Allow-Origin": "https://trusted"})
    assert _check_cors_wildcard(t) == []


def test_cors_absent_ok():
    assert _check_cors_wildcard(Target(url="https://x/", headers={})) == []


# --- permissions policy ----------------------------------------------------

def test_permissions_policy_missing():
    assert _check_permissions_policy(Target(url="https://x/", headers={})) != []


def test_permissions_policy_present():
    t = Target(url="https://x/", headers={"Permissions-Policy": "geolocation=()"})
    assert _check_permissions_policy(t) == []


def test_feature_policy_satisfies():
    t = Target(url="https://x/", headers={"Feature-Policy": "geolocation 'none'"})
    assert _check_permissions_policy(t) == []


# --- clear-text form -------------------------------------------------------

def test_clear_text_password_form_http_action():
    t = Target(url="https://x/", body='<form action="http://x/login"><input type="password"></form>')
    assert _check_clear_text_form(t) != []


def test_password_form_https_action_ok():
    t = Target(url="https://x/", body='<form action="https://x/login"><input type="password"></form>')
    assert _check_clear_text_form(t) == []


def test_no_password_field_no_finding():
    t = Target(url="https://x/", body='<form action="http://x/q"><input type="text"></form>')
    assert _check_clear_text_form(t) == []


# --- scan_response wrapper + error path -----------------------------------

def test_scan_response_builds_findings():
    findings = scan_response("https://x/", 200, {"Content-Type": "text/html"}, "<html>")
    assert isinstance(findings, list) and findings


def test_request_error_short_circuits():
    t = Target(url="https://x/", error="boom")
    findings = run_passive_checks(t)
    assert len(findings) == 1 and findings[0].rule_id == "request-failed"


def test_broken_check_is_isolated():
    def boom(_t):
        raise ValueError("nope")
    findings = run_passive_checks(
        Target(url="https://x/", status=200, headers={"Content-Type": "application/json"}),
        checks=[("boom", "note", "Boom", boom)])
    assert any(f.rule_id == "check-error" for f in findings)


def test_registry_has_expected_count():
    ids = {c[0] for c in PASSIVE_CHECKS}
    assert {"cors-wildcard", "clear-text-form", "missing-permissions-policy"} <= ids
    assert len(PASSIVE_CHECKS) >= 14
