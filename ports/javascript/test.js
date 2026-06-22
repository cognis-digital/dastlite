// Minimal zero-dependency tests for the JS port (node test.js).
import assert from "assert";
import { runPassiveChecks, scanInput } from "./index.js";

function ids(fs) { return new Set(fs.map((f) => f.rule_id)); }
let n = 0;
function t(name, fn) { fn(); n++; }

t("missing headers on https", () => {
  const fs = runPassiveChecks({ url: "https://x/", status: 200, headers: {} });
  const r = ids(fs);
  for (const id of ["missing-csp", "missing-x-frame-options", "hsts"]) assert(r.has(id), id);
});

t("clean response has no findings", () => {
  const fs = runPassiveChecks({
    url: "https://x/", status: 200, headers: {
      "Content-Security-Policy": "default-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Strict-Transport-Security": "max-age=99999999",
    }, body: "",
  });
  assert.strictEqual(fs.length, 0);
});

t("hsts skipped on http", () => {
  const fs = runPassiveChecks({ url: "http://x/", status: 200, headers: {} });
  assert(!ids(fs).has("hsts"));
});

t("cookie missing flags", () => {
  const fs = runPassiveChecks({ url: "https://x/", headers: { "Set-Cookie": "a=b" } });
  assert(ids(fs).has("cookie-flags"));
});

t("cors wildcard", () => {
  const fs = runPassiveChecks({ url: "https://x/", headers: { "Access-Control-Allow-Origin": "*" } });
  assert(ids(fs).has("cors-wildcard"));
});

t("info disclosure AWS key", () => {
  const fs = runPassiveChecks({ url: "https://x/", headers: {}, body: "AKIAIOSFODNN7EXAMPLE" });
  const f = fs.find((x) => x.rule_id === "info-disclosure");
  assert(f && f.level === "error");
});

t("case-insensitive headers", () => {
  const fs = runPassiveChecks({ url: "https://x/", headers: { "content-security-policy": "x", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer", "strict-transport-security": "max-age=99999999" } });
  assert(!ids(fs).has("missing-csp"));
});

t("scanInput multi-record", () => {
  const out = scanInput({ responses: [{ url: "https://x/", headers: {} }, { url: "http://y/", headers: {} }] });
  assert(out.tool === "dastlite" && out.score === out.findings.length && out.findings.length > 0);
});

console.log(`ok - ${n} JS port tests passed`);
