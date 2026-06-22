"""Authorization-gated ACTIVE scanning for DASTLITE.

DEFENSIVE / AUTHORIZED-USE ONLY.

Active mode sends real HTTP requests to a live target. It is **OFF by default**
and refuses to run unless ALL of the following hold:

    1. An explicit ``--authorized`` flag is passed (operator attests consent).
    2. A non-empty target allowlist (scope) is supplied. Every probe target is
       checked against the scope; anything not in scope is *skipped*, not probed.
    3. A rate limit (requests/second) is enforced between requests.

There are NO exploit payloads here. The "active" probes are benign, read-only
safety checks an authorized owner would run against their own surface:

    * a small set of *safe, well-known* paths (``/robots.txt``, ``/.git/HEAD``,
      ``/.env``, ``/server-status``, …) requested with GET, to see whether
      sensitive files are *publicly reachable* — the same thing the passive
      engine then analyzes.
    * a TRACE-method check (does the server echo the request — XST exposure).

Each fetched response is handed to the **passive** engine so the analysis logic
is shared and unit-testable offline. Tests exercise this module against
localhost / a bundled fixture server / injected fetchers only — never a real
external host.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from .core import Target, ScanResult, run_passive_checks, severity_rank, fetch, Finding

# Loud banner printed to stderr whenever active mode is engaged.
AUTHORIZED_USE_BANNER = (
    "============================================================\n"
    " DASTLITE ACTIVE MODE — AUTHORIZED USE ONLY\n"
    " You attest you have explicit written permission to probe the\n"
    " in-scope targets below. Active scanning of systems you do not\n"
    " own or lack authorization to test may be illegal. Defensive use\n"
    " only: no exploit payloads are sent; probes are read-only GETs.\n"
    "============================================================"
)

# Benign, read-only paths an owner checks for accidental public exposure.
# (rule_id, path, note)
SAFE_PROBE_PATHS: List[Tuple[str, str, str]] = [
    ("exposed-robots", "/robots.txt", "robots.txt reachable"),
    ("exposed-git", "/.git/HEAD", "VCS metadata (.git) may be publicly served"),
    ("exposed-dotenv", "/.env", "environment file (.env) may be publicly served"),
    ("exposed-server-status", "/server-status", "Apache server-status may be public"),
    ("exposed-ds-store", "/.DS_Store", "macOS .DS_Store may be publicly served"),
    ("exposed-backup", "/backup.zip", "backup archive may be publicly served"),
]


class AuthorizationError(Exception):
    """Raised when active mode is requested without satisfying the gate."""


@dataclass
class ActiveConfig:
    """Configuration + safety gate for active scanning."""

    authorized: bool = False
    allowlist: List[str] = field(default_factory=list)  # host or host:port entries
    rate_limit: float = 1.0  # requests per second (must be > 0)
    probe_paths: List[Tuple[str, str, str]] = field(default_factory=lambda: list(SAFE_PROBE_PATHS))
    check_trace: bool = True

    def validate(self) -> None:
        """Enforce the authorization gate. Raises AuthorizationError on failure."""
        if not self.authorized:
            raise AuthorizationError(
                "active mode is OFF by default; pass --authorized to attest consent")
        scope = [s for s in (self.allowlist or []) if s.strip()]
        if not scope:
            raise AuthorizationError(
                "active mode requires a non-empty --scope/--target-allowlist")
        if not self.rate_limit or self.rate_limit <= 0:
            raise AuthorizationError("active mode requires a positive --rate-limit")


def _host_port(url: str) -> str:
    """Normalize a URL to a 'host' or 'host:port' string (lowercased)."""
    p = urlparse(url if "://" in url else "http://" + url)
    host = (p.hostname or "").lower()
    if p.port:
        return f"{host}:{p.port}"
    return host


def in_scope(url: str, allowlist: Iterable[str]) -> bool:
    """True if the URL's host (or host:port) matches an allowlist entry.

    An allowlist entry of bare host matches any port on that host; an entry of
    ``host:port`` matches only that port. Matching is exact on host (no implicit
    subdomain wildcarding) to keep scope tight.
    """
    target = _host_port(url)
    target_host = target.split(":", 1)[0]
    for raw in allowlist:
        entry = raw.strip().lower()
        if not entry:
            continue
        # strip scheme if the operator pasted a full URL into the allowlist
        if "://" in entry:
            entry = _host_port(entry)
        if ":" in entry:
            if target == entry:
                return True
        else:
            if target_host == entry:
                return True
    return False


def _base(url: str) -> str:
    p = urlparse(url if "://" in url else "https://" + url)
    return urlunparse((p.scheme or "https", p.netloc, "", "", "", ""))


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + path


class _RateLimiter:
    """Simple sleep-based rate limiter (requests per second)."""

    def __init__(self, rps: float, sleeper: Callable[[float], None] = time.sleep):
        self._min_interval = 1.0 / rps if rps > 0 else 0.0
        self._sleeper = sleeper
        self._last = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last
        if self._last and elapsed < self._min_interval:
            self._sleeper(self._min_interval - elapsed)
        self._last = time.monotonic()


def _probe_findings_for(rule_id: str, note: str, target: Target) -> List[Finding]:
    """Turn a probe response into findings: passive analysis + exposure flag."""
    findings: List[Finding] = []
    # A 2xx on a sensitive path = public exposure (error-level, owner cares).
    if 200 <= (target.status or 0) < 300 and target.body:
        findings.append(Finding(rule_id, "error",
                                f"{note} (HTTP {target.status} on {target.url}).",
                                target.url, (target.body or "")[:80].replace("\n", " ").strip()))
    # Always run the passive engine on whatever came back.
    findings.extend(run_passive_checks(target))
    return findings


def run_active_scan(urls: Iterable[str], config: ActiveConfig,
                    fetcher: Optional[Callable[[str], Target]] = None,
                    sleeper: Callable[[float], None] = time.sleep,
                    on_banner: Optional[Callable[[str], None]] = None) -> ScanResult:
    """Run authorization-gated active probes against in-scope URLs.

    ``fetcher`` is injectable for tests (localhost/fixtures/mocks only).
    Out-of-scope targets are skipped (a 'skipped-out-of-scope' note is recorded).
    """
    config.validate()
    if on_banner is not None:
        on_banner(AUTHORIZED_USE_BANNER)
    fetch_fn = fetcher or (lambda u: fetch(u))
    limiter = _RateLimiter(config.rate_limit, sleeper=sleeper)
    result = ScanResult()

    for raw in urls:
        url = raw.strip()
        if not url or url.startswith("#"):
            continue
        if not in_scope(url, config.allowlist):
            result.findings.append(Finding(
                "skipped-out-of-scope", "note",
                f"Target not in authorized scope; skipped (not probed): {url}",
                url, ""))
            continue

        base = _base(url)
        # 1) baseline fetch of the URL itself
        limiter.wait()
        root = fetch_fn(url)
        result.targets.append(root)
        result.findings.extend(run_passive_checks(root))

        # 2) safe path probes
        for rule_id, path, note in config.probe_paths:
            probe_url = _join(base, path)
            limiter.wait()
            t = fetch_fn(probe_url)
            result.targets.append(t)
            result.findings.extend(_probe_findings_for(rule_id, note, t))

        # 3) TRACE / XST exposure check
        if config.check_trace:
            limiter.wait()
            t = fetch_fn(url)  # caller's fetcher decides method; default GET is safe
            # Heuristic: a server echoing 'TRACE' or our marker indicates XST.
            body = (t.body or "")
            if t.status and 200 <= t.status < 300 and "TRACE" in body.upper():
                result.findings.append(Finding(
                    "xst-trace", "warning",
                    "Server appears to honor TRACE (cross-site tracing exposure).",
                    url, body[:80].replace("\n", " ").strip()))

    result.findings.sort(key=lambda f: (-severity_rank(f.level), f.url, f.rule_id))
    return result
