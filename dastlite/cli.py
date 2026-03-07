"""Command-line interface for DASTLITE.

Examples
--------
    # Scan a few URLs and print a table
    dastlite scan https://example.com https://example.org

    # Scan everything listed in a file (one URL per line, # comments ok)
    dastlite scan --targets demos/01-basic/targets.txt

    # Emit SARIF for upload to GitHub code scanning
    dastlite scan --targets urls.txt --format sarif -o results.sarif

    # CI gate: fail the build if any 'warning' (or worse) is found
    dastlite scan --targets urls.txt --fail-on warning --format json

Exit codes:
    0  clean (no finding at/above --fail-on)
    1  findings at/above --fail-on threshold were reported
    2  usage / input error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import scan_targets, to_sarif, to_json, severity_rank


def _load_targets(args) -> list:
    urls = list(args.urls or [])
    if args.targets:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Config-as-code baseline DAST: crawl a URL list, run passive "
                    "security checks, emit SARIF. A 5-minute PR-gate DAST.",
        epilog="Example: dastlite scan --targets urls.txt --format sarif -o out.sarif --fail-on warning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan URLs and report passive findings.",
                          description="Fetch each URL and run passive DAST checks.")
    scan.add_argument("urls", nargs="*", help="One or more URLs to scan.")
    scan.add_argument("--targets", "-t", metavar="FILE",
                      help="File with one URL per line (# comments allowed).")
    scan.add_argument("--format", "-f", choices=["table", "json", "sarif"],
                      default="table", help="Output format (default: table).")
    scan.add_argument("--output", "-o", metavar="FILE",
                      help="Write report to FILE instead of stdout.")
    scan.add_argument("--fail-on", choices=["error", "warning", "note", "never"],
                      default="error",
                      help="Exit non-zero if a finding at/above this level exists "
                           "(default: error).")
    scan.add_argument("--timeout", type=float, default=10.0,
                      help="Per-request timeout in seconds (default: 10).")
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 0

    urls = _load_targets(args)
    if not urls:
        print("error: no targets given. Pass URLs or --targets FILE.", file=sys.stderr)
        return 2

    result = scan_targets(urls, timeout=args.timeout)

    # Render
    if args.format == "table":
        out = None
    elif args.format == "json":
        out = json.dumps(to_json(result), indent=2)
    else:  # sarif
        out = json.dumps(to_sarif(result), indent=2)

    if args.output:
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

    # Exit-code gating for CI.
    if args.fail_on == "never":
        return 0
    threshold = severity_rank(args.fail_on)
    triggered = any(severity_rank(f.level) >= threshold for f in result.findings)
    return 1 if triggered else 0


if __name__ == "__main__":
    sys.exit(main())
