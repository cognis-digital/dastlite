// TypeScript port of the dastlite PASSIVE core. Pure + offline; same rule IDs
// and JSON shape as the Python reference.

export interface Target {
  url?: string;
  status?: number;
  headers?: Record<string, string>;
  body?: string;
}

export interface Finding {
  rule_id: string;
  level: "error" | "warning" | "note";
  message: string;
  url: string;
}

const SEC_HEADERS: ReadonlyArray<[string, string, Finding["level"]]> = [
  ["missing-csp", "Content-Security-Policy", "warning"],
  ["missing-x-content-type-options", "X-Content-Type-Options", "warning"],
  ["missing-x-frame-options", "X-Frame-Options", "warning"],
  ["missing-referrer-policy", "Referrer-Policy", "note"],
];

function header(headers: Record<string, string> | undefined, name: string): string | null {
  const low = name.toLowerCase();
  for (const k of Object.keys(headers ?? {})) {
    if (k.toLowerCase() === low) return headers![k];
  }
  return null;
}

export function runPassiveChecks(t: Target): Finding[] {
  const findings: Finding[] = [];
  const url = t.url ?? "";
  const h = t.headers ?? {};
  const isHttps = url.toLowerCase().startsWith("https://");

  for (const [id, name, level] of SEC_HEADERS) {
    if (header(h, name) === null) {
      findings.push({ rule_id: id, level, message: `Missing ${name} header.`, url });
    }
  }

  if (isHttps) {
    const hsts = header(h, "Strict-Transport-Security");
    const m = hsts ? /max-age\s*=\s*(\d+)/i.exec(hsts) : null;
    if (!hsts || !m || parseInt(m[1], 10) < 86400) {
      findings.push({ rule_id: "hsts", level: "warning", message: "Weak or missing HSTS.", url });
    }
  }

  const cookie = header(h, "Set-Cookie");
  if (cookie) {
    const low = cookie.toLowerCase();
    if (!low.includes("httponly"))
      findings.push({ rule_id: "cookie-flags", level: "warning", message: "Cookie missing HttpOnly.", url });
    if (isHttps && !low.includes("secure"))
      findings.push({ rule_id: "cookie-flags", level: "warning", message: "Cookie missing Secure.", url });
    if (!low.includes("samesite"))
      findings.push({ rule_id: "cookie-flags", level: "warning", message: "Cookie missing SameSite.", url });
  }

  const acao = header(h, "Access-Control-Allow-Origin");
  if (acao && acao.trim() === "*") {
    findings.push({ rule_id: "cors-wildcard", level: "warning", message: "CORS Access-Control-Allow-Origin is '*'.", url });
  }

  const body = t.body ?? "";
  if (/AKIA[0-9A-Z]{16}/.test(body) || /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(body)) {
    findings.push({ rule_id: "info-disclosure", level: "error", message: "Secret material in body.", url });
  }

  return findings;
}

export function scanInput(data: unknown): { tool: string; findings: Finding[]; score: number } {
  let records: Target[] = [];
  if (Array.isArray(data)) records = data as Target[];
  else if (data && typeof data === "object" && Array.isArray((data as any).responses))
    records = (data as any).responses;
  else if (data && typeof data === "object") records = [data as Target];
  const findings: Finding[] = [];
  for (const rec of records) if (rec && typeof rec === "object") findings.push(...runPassiveChecks(rec));
  return { tool: "dastlite", findings, score: findings.length };
}
