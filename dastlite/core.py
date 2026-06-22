"""Core DAST engine for DASTLITE.

Everything here is importable and pure-ish: the passive checks operate on a
captured HTTP response (status, headers, body) so they can be unit tested
with no network. ``fetch`` and ``scan_targets`` add the live HTTP layer.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

TOOL_NAME = "dastlite"
TOOL_VERSION = "1.0.0"
INFORMATION_URI = "https://github.com/cognis-digital/dastlite"

# Severity ordering (high = worst). Used for sorting + exit-code gating.
_SEVERITY_ORDER = {"error": 3, "warning": 2, "note": 1, "none": 0}


def severity_rank(level: str) -> int:
    """Numeric rank for a SARIF level string (higher = more severe)."""
    return _SEVERITY_ORDER.get(level, 0)


@dataclass
class Finding:
    """A single passive-check finding for one target."""

    rule_id: str
    level: str  # SARIF level: error|warning|note
    message: str
    url: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "level": self.level,
            "message": self.message,
            "url": self.url,
            "evidence": self.evidence,
        }


@dataclass
class Target:
    """A captured HTTP response for one URL."""

    url: str
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    error: Optional[str] = None

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup."""
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return None


@dataclass
class ScanResult:
    """Aggregate result across all scanned targets."""

    targets: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    @property
    def worst_level(self) -> str:
        worst = "none"
        for f in self.findings:
            if severity_rank(f.level) > severity_rank(worst):
                worst = f.level
        return worst

    def counts(self) -> dict:
        out = {"error": 0, "warning": 0, "note": 0}
        for f in self.findings:
            if f.level in out:
                out[f.level] += 1
        return out


# --------------------------------------------------------------------------
# Passive checks. Each check: (rule_id, level, title, fn) where
# fn(target) -> list[(message, evidence)].  Empty list = no finding.
# --------------------------------------------------------------------------

CheckFn = Callable[[Target], list]


def _check_missing_security_header(name: str, advice: str) -> CheckFn:
    def _fn(t: Target) -> list:
        if t.header(name) is None:
            return [(f"Missing {name} header. {advice}", "")]
        return []

    return _fn


def _check_hsts(t: Target) -> list:
    if not t.url.lower().startswith("https://"):
        return []
    val = t.header("Strict-Transport-Security")
    if val is None:
        return [("HTTPS response is missing Strict-Transport-Security (HSTS).", "")]
    m = re.search(r"max-age\s*=\s*(\d+)", val, re.I)
    if not m or int(m.group(1)) < 86400:
        return [("HSTS max-age is missing or shorter than 1 day.", val)]
    return []


def _check_cookie_flags(t: Target) -> list:
    findings = []
    is_https = t.url.lower().startswith("https://")
    for k, v in t.headers.items():
        if k.lower() != "set-cookie":
            continue
        # A header value may technically join multiple cookies; split safely.
        for cookie in re.split(r",(?=[^;]+=)", v):
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            if "httponly" not in low:
                findings.append((f"Cookie '{name}' is missing the HttpOnly flag.", cookie.strip()))
            if is_https and "secure" not in low:
                findings.append((f"Cookie '{name}' is missing the Secure flag.", cookie.strip()))
            if "samesite" not in low:
                findings.append((f"Cookie '{name}' is missing the SameSite attribute.", cookie.strip()))
    return findings


def _check_server_banner(t: Target) -> list:
    findings = []
    for hdr in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        val = t.header(hdr)
        if val and re.search(r"\d", val):
            findings.append((f"{hdr} header leaks software/version: {val}", val))
        elif val and hdr in ("X-Powered-By", "X-AspNet-Version"):
            findings.append((f"{hdr} header is present and reveals technology: {val}", val))
    return findings


def _check_content_type(t: Target) -> list:
    ct = t.header("Content-Type")
    if ct is None and t.status and 200 <= t.status < 300:
        return [("2xx response is missing a Content-Type header.", "")]
    if ct and "charset" not in ct.lower() and "text/html" in ct.lower():
        return [("text/html response does not declare a charset.", ct)]
    return []


def _check_cache_sensitive(t: Target) -> list:
    # Pages that set cookies should not be cacheable.
    has_cookie = any(k.lower() == "set-cookie" for k in t.headers)
    if not has_cookie:
        return []
    cc = (t.header("Cache-Control") or "").lower()
    if "no-store" in cc or "private" in cc:
        return []
    return [("Response sets a cookie but is not marked no-store/private (cacheable secret risk).", t.header("Cache-Control") or "<missing>")]


_INFO_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Private key material in response body."),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id in response body."),
    (re.compile(r"(?i)(stack trace|traceback \(most recent call last\))"), "Stack trace / debug output in response body."),
    (re.compile(r"(?i)<title>\s*(?:exception|error)\b"), "Error page leaks exception details."),
    (re.compile(r"(?i)\b(sql syntax|you have an error in your sql)\b"), "SQL error message in response body."),
]


def _check_info_disclosure(t: Target) -> list:
    findings = []
    body = t.body or ""
    snippet_window = 60
    for pat, msg in _INFO_PATTERNS:
        m = pat.search(body)
        if m:
            start = max(0, m.start() - 10)
            findings.append((msg, body[start:start + snippet_window].replace("\n", " ").strip()))
    return findings


def _check_mixed_content(t: Target) -> list:
    if not t.url.lower().startswith("https://"):
        return []
    body = t.body or ""
    # active mixed content (scripts/iframes/links) loaded over http
    m = re.search(r'(?:src|href)\s*=\s*["\']http://[^"\']+', body, re.I)
    if m:
        return [("HTTPS page references an http:// resource (mixed content).", m.group(0)[:80])]
    return []


def _check_cors_wildcard(t: Target) -> list:
    """A wildcard ACAO combined with credentials is a misconfiguration."""
    acao = t.header("Access-Control-Allow-Origin")
    if acao is None:
        return []
    findings = []
    if acao.strip() == "*":
        acac = (t.header("Access-Control-Allow-Credentials") or "").lower()
        if acac == "true":
            findings.append(("CORS allows any origin (*) WITH credentials — a serious misconfiguration.", acao))
        else:
            findings.append(("CORS Access-Control-Allow-Origin is wildcard (*).", acao))
    return findings


def _check_permissions_policy(t: Target) -> list:
    if t.header("Permissions-Policy") is None and t.header("Feature-Policy") is None:
        return [("No Permissions-Policy header (powerful features are not restricted).", "")]
    return []


def _check_clear_text_form(t: Target) -> list:
    """A password field posting over http:// leaks credentials in clear text."""
    body = t.body or ""
    if not re.search(r'<input[^>]+type\s*=\s*["\']?password', body, re.I):
        return []
    m = re.search(r'<form[^>]+action\s*=\s*["\']http://[^"\']+', body, re.I)
    if m:
        return [("Password form submits over plain http:// (clear-text credentials).", m.group(0)[:80])]
    return []


# Registry: each entry is (rule_id, level, title, fn)
PASSIVE_CHECKS: list = [
    ("missing-csp", "warning", "Missing Content-Security-Policy",
     _check_missing_security_header("Content-Security-Policy", "Add a CSP to mitigate XSS/injection.")),
    ("missing-x-content-type-options", "warning", "Missing X-Content-Type-Options",
     _check_missing_security_header("X-Content-Type-Options", "Set 'nosniff' to stop MIME sniffing.")),
    ("missing-x-frame-options", "warning", "Missing frame protection",
     _check_missing_security_header("X-Frame-Options", "Set X-Frame-Options or a CSP frame-ancestors directive.")),
    ("missing-referrer-policy", "note", "Missing Referrer-Policy",
     _check_missing_security_header("Referrer-Policy", "Set a Referrer-Policy to limit referrer leakage.")),
    ("hsts", "warning", "Weak or missing HSTS", _check_hsts),
    ("cookie-flags", "warning", "Insecure cookie attributes", _check_cookie_flags),
    ("server-banner", "note", "Verbose server/technology banner", _check_server_banner),
    ("content-type", "note", "Content-Type issues", _check_content_type),
    ("cacheable-secret", "warning", "Cacheable response with cookie", _check_cache_sensitive),
    ("info-disclosure", "error", "Sensitive information disclosure", _check_info_disclosure),
    ("mixed-content", "warning", "Mixed active content", _check_mixed_content),
    ("cors-wildcard", "warning", "Permissive CORS policy", _check_cors_wildcard),
    ("missing-permissions-policy", "note", "Missing Permissions-Policy", _check_permissions_policy),
    ("clear-text-form", "error", "Credentials submitted over clear text", _check_clear_text_form),
]


def run_passive_checks(target: Target, checks: Optional[Iterable] = None) -> list:
    """Run passive checks against a captured ``Target`` and return Findings."""
    if target.error:
        return [Finding("request-failed", "warning",
                        f"Request failed: {target.error}", target.url, "")]
    checks = checks if checks is not None else PASSIVE_CHECKS
    findings = []
    for rule_id, level, _title, fn in checks:
        try:
            for message, evidence in fn(target):
                findings.append(Finding(rule_id, level, message, target.url, evidence))
        except Exception as exc:  # a broken check must not abort the scan
            findings.append(Finding("check-error", "note",
                                    f"Check '{rule_id}' raised: {exc}", target.url, ""))
    return findings


def scan_response(url: str, status: int, headers: dict, body: str = "") -> list:
    """Convenience wrapper: build a Target and run all passive checks."""
    return run_passive_checks(Target(url=url, status=status, headers=dict(headers), body=body))


def target_from_record(rec: dict) -> Target:
    """Build a Target from a captured-response dict (offline, no network).

    Accepts the demo capture shape: ``{url,status,headers,body}``. ``headers``
    may be a dict or a list of ``[name, value]`` / ``{"name","value"}`` pairs
    (as produced by HAR-style captures).
    """
    headers = rec.get("headers", {})
    if isinstance(headers, list):
        norm = {}
        for h in headers:
            if isinstance(h, dict) and "name" in h:
                norm[str(h["name"])] = str(h.get("value", ""))
            elif isinstance(h, (list, tuple)) and len(h) >= 2:
                norm[str(h[0])] = str(h[1])
        headers = norm
    return Target(
        url=str(rec.get("url", "")),
        status=int(rec.get("status", 0) or 0),
        headers=dict(headers or {}),
        body=str(rec.get("body", "") or ""),
        error=rec.get("error"),
    )


def _iter_records(data) -> list:
    """Normalize loaded JSON into a list of capture records."""
    if isinstance(data, dict):
        for key in ("responses", "captures", "targets", "entries"):
            if isinstance(data.get(key), list):
                return data[key]
        # HAR file: log.entries[*].{request.url, response.{status,headers,content.text}}
        if isinstance(data.get("log"), dict) and isinstance(data["log"].get("entries"), list):
            recs = []
            for e in data["log"]["entries"]:
                req = e.get("request", {})
                resp = e.get("response", {})
                recs.append({
                    "url": req.get("url", ""),
                    "status": resp.get("status", 0),
                    "headers": resp.get("headers", []),
                    "body": (resp.get("content", {}) or {}).get("text", ""),
                })
            return recs
        return [data]
    if isinstance(data, list):
        return data
    return []


def scan_input(data) -> ScanResult:
    """Passive offline scan of one or more captured responses (no network).

    ``data`` is already-parsed JSON (dict/list) in the demo capture shape or a
    HAR document. Returns a fully-populated ScanResult.
    """
    result = ScanResult()
    for rec in _iter_records(data):
        if not isinstance(rec, dict):
            continue
        target = target_from_record(rec)
        result.targets.append(target)
        result.findings.extend(run_passive_checks(target))
    result.findings.sort(key=lambda f: (-severity_rank(f.level), f.url, f.rule_id))
    return result


def scan_input_file(path: str) -> ScanResult:
    """Load a JSON capture file and run a passive offline scan."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return scan_input(data)


# --------------------------------------------------------------------------
# Live HTTP layer
# --------------------------------------------------------------------------

def fetch(url: str, timeout: float = 10.0, max_body: int = 200_000,
          user_agent: str = f"{TOOL_NAME}/{TOOL_VERSION}") -> Target:
    """Fetch a URL and capture status/headers/body into a Target.

    Network errors are captured on ``Target.error`` rather than raised, so a
    single dead URL does not abort the whole scan.
    """
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(max_body)
            charset = resp.headers.get_content_charset() or "utf-8"
            body = raw.decode(charset, errors="replace")
            headers = {k: v for k, v in resp.headers.items()}
            return Target(url=url, status=resp.status, headers=headers, body=body)
    except urllib.error.HTTPError as e:
        # An HTTP error response is still a real response we can inspect.
        try:
            raw = e.read(max_body)
            body = raw.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        headers = {k: v for k, v in (e.headers.items() if e.headers else [])}
        return Target(url=url, status=e.code, headers=headers, body=body)
    except Exception as e:  # URLError, timeout, ssl, etc.
        return Target(url=url, error=str(e))


def scan_targets(urls: Iterable[str], timeout: float = 10.0,
                 fetcher: Optional[Callable[[str], Target]] = None) -> ScanResult:
    """Fetch each URL and run passive checks. Returns a ScanResult.

    ``fetcher`` can be injected (e.g. for tests) to avoid real network calls.
    """
    fetch_fn = fetcher or (lambda u: fetch(u, timeout=timeout))
    result = ScanResult()
    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        target = fetch_fn(url)
        result.targets.append(target)
        result.findings.extend(run_passive_checks(target))
    # Sort worst-first for stable, useful output.
    result.findings.sort(key=lambda f: (-severity_rank(f.level), f.url, f.rule_id))
    return result


# --------------------------------------------------------------------------
# Reporters
# --------------------------------------------------------------------------

def _rule_descriptors() -> list:
    rules = []
    for rule_id, level, title, _fn in PASSIVE_CHECKS:
        rules.append({
            "id": rule_id,
            "name": title,
            "shortDescription": {"text": title},
            "defaultConfiguration": {"level": level},
        })
    # synthetic rules emitted at runtime
    for rid, title in (("request-failed", "Request failed"), ("check-error", "Check error"),
                       ("skipped-out-of-scope", "Skipped: out of authorized scope"),
                       ("xst-trace", "Cross-site tracing (TRACE)"),
                       ("exposed-git", "Exposed VCS metadata"),
                       ("exposed-dotenv", "Exposed environment file"),
                       ("exposed-robots", "robots.txt reachable"),
                       ("exposed-server-status", "Exposed server-status"),
                       ("exposed-ds-store", "Exposed .DS_Store"),
                       ("exposed-backup", "Exposed backup archive")):
        rules.append({"id": rid, "name": title,
                      "shortDescription": {"text": title}})
    return rules


def to_sarif(result: ScanResult) -> dict:
    """Render a ScanResult as a SARIF 2.1.0 document (dict)."""
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.rule_id,
            "level": f.level,
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url}
                }
            }],
            "properties": {"evidence": f.evidence} if f.evidence else {},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": INFORMATION_URI,
                    "rules": _rule_descriptors(),
                }
            },
            "results": results,
        }],
    }


def to_json(result: ScanResult) -> dict:
    """Render a ScanResult as a plain JSON-able dict."""
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "summary": {
            "targets": len(result.targets),
            "findings": len(result.findings),
            "counts": result.counts(),
            "worst_level": result.worst_level,
        },
        "targets": [{"url": t.url, "status": t.status, "error": t.error} for t in result.targets],
        "findings": [f.to_dict() for f in result.findings],
    }
