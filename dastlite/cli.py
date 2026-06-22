"""Command-line interface for DASTLITE.

DASTLITE has three modes:

  scan         PASSIVE live scan: fetch each URL once and run passive checks.
  scan-input   PASSIVE offline scan: analyze captured responses from a JSON/HAR
               file. No network at all — the safe default for CI on artifacts.
  active       ACTIVE scan (AUTHORIZED USE ONLY): send extra read-only probes to
               a live, in-scope target. OFF by default; requires --authorized,
               a --scope allowlist, and a --rate-limit. No exploit payloads.

Examples
--------
    # Passive live scan and print a table
    dastlite scan https://example.com https://example.org

    # Passive OFFLINE scan of a captured response (no network)
    dastlite scan-input capture.json --format sarif -o out.sarif

    # Active scan — authorized use only, scope + rate-limit enforced
    dastlite active https://app.example.com \\
        --authorized --scope app.example.com --rate-limit 2

Exit codes:
    0  clean (no finding at/above --fail-on)
    1  findings at/above --fail-on threshold were reported
    2  usage / input / authorization error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    scan_targets, scan_input_file, to_sarif, to_json, severity_rank,
)


def _load_targets(args) -> list:
    urls = list(getattr(args, "urls", None) or [])
    if getattr(args, "targets", None):
        try:
            with open(args.targets, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
        except OSError as e:
            print(f"error: cannot read targets file: {e}", file=sys.stderr)
            return []
    return urls


def _load_scope(args) -> list:
    scope = list(getattr(args, "scope", None) or [])
    if getattr(args, "scope_file", None):
        try:
            with open(args.scope_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        scope.append(line)
        except OSError as e:
            print(f"error: cannot read scope file: {e}", file=sys.stderr)
            return []
    return scope


def _print_table(result, stream) -> None:
    counts = result.counts()
    if not result.findings:
        print("No findings. All targets passed passive checks.", file=stream)
    else:
        print(f"{'LEVEL':<8} {'RULE':<28} URL", file=stream)
        print("-" * 80, file=stream)
        for f in result.findings:
            print(f"{f.level:<8} {f.rule_id:<28} {f.url}", file=stream)
            print(f"         {f.message}", file=stream)
            if f.evidence:
                print(f"         evidence: {f.evidence}", file=stream)
    print("", file=stream)
    print(f"Scanned {len(result.targets)} target(s) | "
          f"errors={counts['error']} warnings={counts['warning']} notes={counts['note']}",
          file=stream)


def _render(result, args) -> int:
    if args.format == "table":
        out = None
    elif args.format == "json":
        out = json.dumps(to_json(result), indent=2)
    else:  # sarif
        out = json.dumps(to_sarif(result), indent=2)

    if getattr(args, "output", None):
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                if out is None:
                    _print_table(result, fh)
                else:
                    fh.write(out + "\n")
        except OSError as e:
            print(f"error: cannot write output: {e}", file=sys.stderr)
            return 2
    else:
        if out is None:
            _print_table(result, sys.stdout)
        else:
            print(out)

    if args.fail_on == "never":
        return 0
    threshold = severity_rank(args.fail_on)
    triggered = any(severity_rank(f.level) >= threshold for f in result.findings)
    return 1 if triggered else 0


def _add_output_args(p) -> None:
    p.add_argument("--format", "-f", choices=["table", "json", "sarif"],
                   default="table", help="Output format (default: table).")
    p.add_argument("--output", "-o", metavar="FILE",
                   help="Write report to FILE instead of stdout.")
    p.add_argument("--fail-on", choices=["error", "warning", "note", "never"],
                   default="error",
                   help="Exit non-zero if a finding at/above this level exists "
                        "(default: error).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Config-as-code baseline DAST. PASSIVE by default; an "
                    "authorization-gated ACTIVE mode is available for owners.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")

    sub = parser.add_subparsers(dest="command")

    # --- passive live scan -------------------------------------------------
    scan = sub.add_parser("scan", help="PASSIVE live scan of URLs.",
                          description="Fetch each URL once and run passive DAST checks (no probing).")
    scan.add_argument("urls", nargs="*", help="One or more URLs to scan.")
    scan.add_argument("--targets", "-t", metavar="FILE",
                      help="File with one URL per line (# comments allowed).")
    scan.add_argument("--timeout", type=float, default=10.0,
                      help="Per-request timeout in seconds (default: 10).")
    _add_output_args(scan)

    # --- passive offline scan ---------------------------------------------
    si = sub.add_parser("scan-input", help="PASSIVE offline scan of a capture file (no network).",
                        description="Analyze captured responses (JSON or HAR) offline. No network.")
    si.add_argument("input", help="JSON/HAR capture file of responses to analyze.")
    _add_output_args(si)

    # --- active scan (gated) ----------------------------------------------
    act = sub.add_parser(
        "active",
        help="ACTIVE scan (AUTHORIZED USE ONLY) — off by default, scope + rate-limit required.",
        description="Send read-only safety probes to a LIVE, in-scope target you own / are "
                    "authorized to test. No exploit payloads. Requires --authorized, --scope, "
                    "and --rate-limit.")
    act.add_argument("urls", nargs="*", help="One or more in-scope URLs to actively probe.")
    act.add_argument("--targets", "-t", metavar="FILE",
                     help="File with one URL per line (# comments allowed).")
    act.add_argument("--authorized", action="store_true",
                     help="REQUIRED. Attest you have explicit permission to probe the targets.")
    act.add_argument("--scope", "--target-allowlist", dest="scope", action="append",
                     metavar="HOST[:PORT]",
                     help="Allowlist entry; repeatable. Only in-scope targets are probed.")
    act.add_argument("--scope-file", metavar="FILE",
                     help="File with one allowlist entry per line.")
    act.add_argument("--rate-limit", type=float, default=1.0, dest="rate_limit",
                     help="Requests/second cap (must be > 0; default: 1).")
    act.add_argument("--timeout", type=float, default=10.0,
                     help="Per-request timeout in seconds (default: 10).")
    _add_output_args(act)
    return parser


def _run_active(args) -> int:
    from .active import ActiveConfig, run_active_scan, AuthorizationError
    urls = _load_targets(args)
    if not urls:
        print("error: no targets given. Pass URLs or --targets FILE.", file=sys.stderr)
        return 2
    config = ActiveConfig(
        authorized=bool(args.authorized),
        allowlist=_load_scope(args),
        rate_limit=args.rate_limit,
    )
    try:
        config.validate()
    except AuthorizationError as e:
        print(f"error: active mode refused: {e}", file=sys.stderr)
        return 2

    def banner(text: str) -> None:
        print(text, file=sys.stderr)

    from .core import fetch as _fetch
    result = run_active_scan(
        urls, config,
        fetcher=lambda u: _fetch(u, timeout=args.timeout),
        on_banner=banner,
    )
    return _render(result, args)


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan-input":
        try:
            result = scan_input_file(args.input)
        except OSError as e:
            print(f"error: cannot read input file: {e}", file=sys.stderr)
            return 2
        except json.JSONDecodeError as e:
            print(f"error: input is not valid JSON: {e}", file=sys.stderr)
            return 2
        return _render(result, args)

    if args.command == "active":
        return _run_active(args)

    if args.command == "scan":
        urls = _load_targets(args)
        if not urls:
            print("error: no targets given. Pass URLs or --targets FILE.", file=sys.stderr)
            return 2
        result = scan_targets(urls, timeout=args.timeout)
        return _render(result, args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
