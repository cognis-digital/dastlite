# Ports of dastlite

The **passive core** of dastlite, ported across languages so you can drop it into
any stack or ship a single static binary. Every port implements the same passive
checks (missing/weak security headers, insecure cookie flags, wildcard CORS,
secret-in-body) over a **captured HTTP response** and emits the same JSON shape
(`{tool, findings:[{rule_id, level, message, url}], score}`). Input is a capture
file: `{ "responses": [ {url, status, headers, body}, ... ] }` (or a single record).

All ports are **offline** — they analyze a capture you provide and make no network
calls. (Live fetching + the authorization-gated active mode live only in the
Python reference: `dastlite scan` / `dastlite active`.)

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../dastlite/` | `dastlite scan-input capture.json` | `pytest` |
| JavaScript / Node | `javascript/` | `node index.js capture.json` | `node test.js` |
| TypeScript | `typescript/` | `npm run build` then import `scanInput` | `npm test` |
| Go | `go/` | `go run . capture.json` | `go test ./...` |
| Rust | `rust/` | `cargo run -- capture.json` | `cargo test` |

> Go and Rust are built + tested on GitHub runners (`.github/workflows/ports.yml`).
> They are **not** verified locally — see CI for green status.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see ../CONTRIBUTING.md.
