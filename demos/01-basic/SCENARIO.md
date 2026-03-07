# Demo 01 - Basic passive DAST scan

This demo shows DASTLITE running its passive security checks against a
captured HTTP response, with **no network access required**.

## What it shows

The sample response (`sample_response.json`) is a realistic but deliberately
insecure HTTPS page:

- No `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
  or `Referrer-Policy` headers.
- No `Strict-Transport-Security` (HSTS) on an HTTPS URL.
- A `Set-Cookie` for `session` that is missing `HttpOnly`, `Secure`, and
  `SameSite`, and the page is cacheable (no `no-store`/`private`).
- A verbose `Server: Apache/2.4.49` and `X-Powered-By: PHP/7.2.1` banner.
- A leaked AWS access key id and a stack trace in the body
  (information disclosure).
- A mixed-content `http://` script reference on an HTTPS page.

## How to run

The checks operate on a captured response, so you can replay the demo file
directly via the library:

```python
import json
from dastlite import scan_response, ScanResult, to_sarif

r = json.load(open("demos/01-basic/sample_response.json"))
findings = scan_response(r["url"], r["status"], r["headers"], r["body"])
for f in findings:
    print(f.level, f.rule_id, f.message)
```

To scan a live URL list instead:

```bash
dastlite scan --targets demos/01-basic/targets.txt --format sarif -o out.sarif --fail-on warning
```

## Expected result

Many findings are reported, including at least one `error`-level
**information disclosure** (AWS key / stack trace), several `warning`s for
missing CSP / X-Frame-Options / HSTS / insecure cookie / mixed content, and
`note`s for the verbose server banner and missing Referrer-Policy.

Because an `error`-level finding exists, a CI run with the default
`--fail-on error` would **exit non-zero (1)**, failing the PR gate.
