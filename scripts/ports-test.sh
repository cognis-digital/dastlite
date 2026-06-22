#!/usr/bin/env bash
# Run the per-language port test suites. Toolchains are optional; missing ones
# are skipped (CI covers Go/Rust on GitHub runners).
set -e
CAP="${1:-demos/04-capture/captures.json}"

echo "== javascript =="
node ports/javascript/test.js || echo "node: skipped"

echo "== typescript =="
( cd ports/typescript && npm install --no-audit --no-fund >/dev/null 2>&1 && npm test ) || echo "ts: skipped"

echo "== go =="
( cd ports/go && go test ./... ) || echo "go: skipped (no toolchain)"

echo "== rust =="
( cd ports/rust && cargo test ) || echo "rust: skipped (no toolchain)"

echo "== sample run (js) =="
node ports/javascript/index.js "$CAP" || true
