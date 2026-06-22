#!/usr/bin/env node
// JavaScript port of the dastlite PASSIVE core: analyze a captured HTTP
// response (status, headers, body) for security-header / cookie issues.
// Pure + offline — same rule IDs and JSON shape as the Python reference.
import { readFileSync } from "fs";
import { pathToFileURL } from "url";

const SEC_HEADERS = [
  ["missing-csp", "Content-Security-Policy", "warning"],
  ["missing-x-content-type-options", "X-Content-Type-Options", "warning"],
  ["missing-x-frame-options", "X-Frame-Options", "warning"],
  ["missing-referrer-policy", "Referrer-Policy", "note"],
];

function header(headers, name) {
  const low = name.toLowerCase();
  for (const k of Object.keys(headers || {})) {
    if (k.toLowerCase() === low) return headers[k];
  }
  return null;
}

// target: { url, status, headers, body }
export function runPassiveChecks(target) {
  const findings = [];
  const h = target.headers || {};
  const isHttps = (target.url || "").toLowerCase().startsWith("https://");

  for (const [id, name, level] of SEC_HEADERS) {
    if (header(h, name) === null) {
      findings.push({ rule_id: id, level, message: `Missing ${name} header.`, url: target.url });
    }
  }

  if (isHttps) {
    const hsts = header(h, "Strict-Transport-Security");
    const m = hsts && /max-age\s*=\s*(\d+)/i.exec(hsts);
    if (!hsts || !m || parseInt(m[1], 10) < 86400) {
      findings.push({ rule_id: "hsts", level: "warning", message: "Weak or missing HSTS.", url: target.url });
    }
  }

  const cookie = header(h, "Set-Cookie");
  if (cookie) {
    const low = cookie.toLowerCase();
    if (!low.includes("httponly"))
      findings.push({ rule_id: "cookie-flags", level: "warning", message: "Cookie missing HttpOnly.", url: target.url });
    if (isHttps && !low.includes("secure"))
      findings.push({ rule_id: "cookie-flags", level: "warning", message: "Cookie missing Secure.", url: target.url });
    if (!low.includes("samesite"))
      findings.push({ rule_id: "cookie-flags", level: "warning", message: "Cookie missing SameSite.", url: target.url });
  }

  const acao = header(h, "Access-Control-Allow-Origin");
  if (acao && acao.trim() === "*") {
    const cred = (header(h, "Access-Control-Allow-Credentials") || "").toLowerCase() === "true";
    findings.push({ rule_id: "cors-wildcard", level: "warning",
      message: cred ? "CORS '*' with credentials." : "CORS Access-Control-Allow-Origin is '*'.", url: target.url });
  }

  const body = target.body || "";
  if (/AKIA[0-9A-Z]{16}/.test(body) || /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(body))
    findings.push({ rule_id: "info-disclosure", level: "error", message: "Secret material in body.", url: target.url });

  return findings;
}

export function scanInput(data) {
  let records = [];
  if (Array.isArray(data)) records = data;
  else if (data && Array.isArray(data.responses)) records = data.responses;
  else if (data) records = [data];
  const findings = [];
  for (const rec of records) if (rec && typeof rec === "object") findings.push(...runPassiveChecks(rec));
  return { tool: "dastlite", findings, score: findings.length };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const path = process.argv[2];
  const data = JSON.parse(readFileSync(path, "utf8"));
  console.log(JSON.stringify(scanInput(data), null, 2));
}
