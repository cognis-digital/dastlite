import { test } from "node:test";
import assert from "node:assert";
import { runPassiveChecks, scanInput, type Finding } from "../src/index.js";

const ids = (fs: Finding[]) => new Set(fs.map((f) => f.rule_id));

test("missing headers on https", () => {
  const r = ids(runPassiveChecks({ url: "https://x/", status: 200, headers: {} }));
  for (const id of ["missing-csp", "missing-x-frame-options", "hsts"]) assert.ok(r.has(id), id);
});

test("clean response", () => {
  const fs = runPassiveChecks({
    url: "https://x/", headers: {
      "Content-Security-Policy": "default-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Strict-Transport-Security": "max-age=99999999",
    },
  });
  assert.strictEqual(fs.length, 0);
});

test("hsts skipped on http", () => {
  assert.ok(!ids(runPassiveChecks({ url: "http://x/", headers: {} })).has("hsts"));
});

test("cookie flags", () => {
  assert.ok(ids(runPassiveChecks({ url: "https://x/", headers: { "Set-Cookie": "a=b" } })).has("cookie-flags"));
});

test("cors wildcard", () => {
  assert.ok(ids(runPassiveChecks({ url: "https://x/", headers: { "Access-Control-Allow-Origin": "*" } })).has("cors-wildcard"));
});

test("info disclosure", () => {
  const fs = runPassiveChecks({ url: "https://x/", body: "AKIAIOSFODNN7EXAMPLE" });
  const f = fs.find((x) => x.rule_id === "info-disclosure");
  assert.ok(f && f.level === "error");
});

test("case-insensitive headers", () => {
  const fs = runPassiveChecks({ url: "https://x/", headers: { "content-security-policy": "x" } });
  assert.ok(!ids(fs).has("missing-csp"));
});

test("scanInput multi-record", () => {
  const out = scanInput({ responses: [{ url: "https://x/", headers: {} }] });
  assert.strictEqual(out.tool, "dastlite");
  assert.strictEqual(out.score, out.findings.length);
  assert.ok(out.findings.length > 0);
});
