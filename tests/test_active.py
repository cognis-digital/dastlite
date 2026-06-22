"""Tests for AUTHORIZATION-GATED active mode.

CRITICAL: every test here uses injected fetchers / mocks. No real network and
no real external host is ever contacted. The point of these tests is to prove
the gate holds (off by default, scope-enforced, rate-limited).
"""
import pytest

from dastlite.active import (
    ActiveConfig, AuthorizationError, in_scope, run_active_scan,
    _host_port, _RateLimiter, AUTHORIZED_USE_BANNER, SAFE_PROBE_PATHS,
)
from dastlite.core import Target
from dastlite.cli import main


# --------------------------------------------------------------------------
# The authorization gate
# --------------------------------------------------------------------------

def test_gate_off_by_default():
    with pytest.raises(AuthorizationError):
        ActiveConfig().validate()


def test_gate_requires_scope():
    with pytest.raises(AuthorizationError):
        ActiveConfig(authorized=True, allowlist=[]).validate()


def test_gate_requires_nonblank_scope():
    with pytest.raises(AuthorizationError):
        ActiveConfig(authorized=True, allowlist=["  ", ""]).validate()


def test_gate_requires_positive_rate_limit():
    with pytest.raises(AuthorizationError):
        ActiveConfig(authorized=True, allowlist=["x"], rate_limit=0).validate()
    with pytest.raises(AuthorizationError):
        ActiveConfig(authorized=True, allowlist=["x"], rate_limit=-1).validate()


def test_gate_passes_when_all_present():
    ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1.0).validate()


def test_run_active_scan_validates_gate():
    with pytest.raises(AuthorizationError):
        list(run_active_scan(["http://localhost/"], ActiveConfig()))


# --------------------------------------------------------------------------
# Scope enforcement
# --------------------------------------------------------------------------

@pytest.mark.parametrize("url,exp", [
    ("http://localhost:8000/x", "localhost:8000"),
    ("https://Example.COM/y", "example.com"),
    ("example.org", "example.org"),
])
def test_host_port(url, exp):
    assert _host_port(url) == exp


def test_in_scope_bare_host_matches_any_port():
    assert in_scope("http://localhost:8000/x", ["localhost"])
    assert in_scope("https://localhost/y", ["localhost"])


def test_in_scope_host_port_is_exact():
    assert in_scope("http://localhost:8000/", ["localhost:8000"])
    assert not in_scope("http://localhost:9999/", ["localhost:8000"])


def test_in_scope_rejects_other_host():
    assert not in_scope("http://evil.example/", ["localhost"])


def test_in_scope_no_subdomain_wildcard():
    # tight scope: app.example does not match sub.app.example
    assert not in_scope("http://sub.app.example/", ["app.example"])


def test_in_scope_accepts_url_entry():
    assert in_scope("http://localhost:8000/x", ["http://localhost:8000"])


def test_out_of_scope_target_is_skipped_not_probed():
    probed = []

    def fetcher(u):
        probed.append(u)
        return Target(url=u, status=200, headers={"Content-Type": "application/json"}, body="{}")

    cfg = ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1000)
    result = run_active_scan(["http://evil.example/"], cfg, fetcher=fetcher,
                             sleeper=lambda s: None)
    assert probed == []  # NEVER fetched
    assert any(f.rule_id == "skipped-out-of-scope" for f in result.findings)


def test_mixed_scope_only_probes_in_scope():
    probed = []

    def fetcher(u):
        probed.append(u)
        return Target(url=u, status=404, headers={"Content-Type": "text/plain"}, body="nf")

    cfg = ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1000)
    run_active_scan(["http://localhost/a", "http://evil.example/b"], cfg,
                    fetcher=fetcher, sleeper=lambda s: None)
    assert all("localhost" in u for u in probed)
    assert probed  # localhost was probed


# --------------------------------------------------------------------------
# Probing behavior (against mock localhost responses)
# --------------------------------------------------------------------------

def _localhost_fetcher(responses):
    def fetcher(u):
        for suffix, resp in responses.items():
            if u.endswith(suffix):
                return resp
        return Target(url=u, status=404, headers={"Content-Type": "text/plain"}, body="not found")
    return fetcher


def test_probes_all_safe_paths():
    seen = []

    def fetcher(u):
        seen.append(u)
        return Target(url=u, status=404, headers={"Content-Type": "text/plain"}, body="nf")

    cfg = ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1000)
    run_active_scan(["http://localhost/"], cfg, fetcher=fetcher, sleeper=lambda s: None)
    for _rid, path, _note in SAFE_PROBE_PATHS:
        assert any(u.endswith(path) for u in seen), f"{path} not probed"


def test_exposed_dotenv_is_error_finding():
    def fetcher(u):
        if u.endswith("/.env"):
            return Target(url=u, status=200, headers={"Content-Type": "text/plain"},
                          body="SECRET_KEY=abc123")
        return Target(url=u, status=404, headers={"Content-Type": "text/plain"}, body="nf")

    cfg = ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1000)
    result = run_active_scan(["http://localhost/"], cfg, fetcher=fetcher, sleeper=lambda s: None)
    env = [f for f in result.findings if f.rule_id == "exposed-dotenv"]
    assert env and env[0].level == "error"


def test_404_on_sensitive_path_no_exposure_finding():
    def fetcher(u):
        return Target(url=u, status=404, headers={"Content-Type": "text/plain"}, body="nf")

    cfg = ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1000,
                       check_trace=False)
    result = run_active_scan(["http://localhost/"], cfg, fetcher=fetcher, sleeper=lambda s: None)
    assert not [f for f in result.findings if f.rule_id == "exposed-dotenv"]


def test_xst_trace_detected():
    def fetcher(u):
        return Target(url=u, status=200, headers={"Content-Type": "text/plain"},
                      body="TRACE / HTTP/1.1 echoed back")

    cfg = ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1000,
                       probe_paths=[])
    result = run_active_scan(["http://localhost/"], cfg, fetcher=fetcher, sleeper=lambda s: None)
    assert any(f.rule_id == "xst-trace" for f in result.findings)


def test_banner_emitted():
    seen = {}

    def banner(text):
        seen["t"] = text

    cfg = ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1000,
                       probe_paths=[], check_trace=False)
    run_active_scan(["http://localhost/"], cfg,
                    fetcher=lambda u: Target(url=u, status=200,
                                             headers={"Content-Type": "application/json"}, body="{}"),
                    sleeper=lambda s: None, on_banner=banner)
    assert "AUTHORIZED USE ONLY" in seen["t"]
    assert "AUTHORIZED USE ONLY" in AUTHORIZED_USE_BANNER


def test_comments_and_blanks_skipped():
    seen = []
    cfg = ActiveConfig(authorized=True, allowlist=["localhost"], rate_limit=1000,
                       probe_paths=[], check_trace=False)
    run_active_scan(["# comment", "", "http://localhost/"], cfg,
                    fetcher=lambda u: seen.append(u) or Target(url=u, status=200,
                        headers={"Content-Type": "application/json"}, body="{}"),
                    sleeper=lambda s: None)
    assert seen == ["http://localhost/"]


# --------------------------------------------------------------------------
# Rate limiter
# --------------------------------------------------------------------------

def test_rate_limiter_sleeps_between_calls():
    slept = []
    rl = _RateLimiter(2.0, sleeper=lambda s: slept.append(s))  # 0.5s interval
    rl.wait()  # first call: no sleep
    rl.wait()  # second call comes immediately -> should sleep ~0.5
    assert slept and slept[0] > 0


def test_rate_limiter_zero_disables():
    slept = []
    rl = _RateLimiter(0, sleeper=lambda s: slept.append(s))
    rl.wait(); rl.wait()
    assert slept == []


# --------------------------------------------------------------------------
# CLI gating
# --------------------------------------------------------------------------

def test_cli_active_refused_without_authorized(capsys):
    rc = main(["active", "http://localhost/", "--scope", "localhost", "--rate-limit", "5"])
    err = capsys.readouterr().err
    assert rc == 2 and "refused" in err.lower()


def test_cli_active_refused_without_scope(capsys):
    rc = main(["active", "http://localhost/", "--authorized", "--rate-limit", "5"])
    assert rc == 2
    assert "scope" in capsys.readouterr().err.lower()


def test_cli_active_no_targets(capsys):
    rc = main(["active", "--authorized", "--scope", "localhost", "--rate-limit", "5"])
    assert rc == 2
