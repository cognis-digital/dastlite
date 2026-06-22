//! Rust port of the dastlite PASSIVE core: analyze a captured HTTP response
//! for security-header / cookie issues. Same rule IDs + JSON shape as Python.
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule_id: String,
    pub level: String,
    pub message: String,
    pub url: String,
}

impl Finding {
    fn new(id: &str, level: &str, msg: &str, url: &str) -> Self {
        Finding { rule_id: id.into(), level: level.into(), message: msg.into(), url: url.into() }
    }
    pub fn to_json(&self) -> Value {
        json!({"rule_id": self.rule_id, "level": self.level, "message": self.message, "url": self.url})
    }
}

/// Case-insensitive header lookup over a JSON object.
fn header<'a>(headers: &'a Value, name: &str) -> Option<&'a str> {
    let low = name.to_lowercase();
    if let Some(obj) = headers.as_object() {
        for (k, v) in obj {
            if k.to_lowercase() == low {
                return v.as_str();
            }
        }
    }
    None
}

fn max_age(value: &str) -> Option<u64> {
    let low = value.to_lowercase();
    let idx = low.find("max-age")?;
    let rest = &low[idx + "max-age".len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Analyze one captured-response record (object with url/status/headers/body).
pub fn run_passive_checks(rec: &Value) -> Vec<Finding> {
    let url = rec.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let headers = rec.get("headers").cloned().unwrap_or(json!({}));
    let body = rec.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let is_https = url.to_lowercase().starts_with("https://");
    let mut fs = Vec::new();

    for (id, name, level) in [
        ("missing-csp", "Content-Security-Policy", "warning"),
        ("missing-x-content-type-options", "X-Content-Type-Options", "warning"),
        ("missing-x-frame-options", "X-Frame-Options", "warning"),
        ("missing-referrer-policy", "Referrer-Policy", "note"),
    ] {
        if header(&headers, name).is_none() {
            fs.push(Finding::new(id, level, &format!("Missing {} header.", name), url));
        }
    }

    if is_https {
        let weak = match header(&headers, "Strict-Transport-Security") {
            None => true,
            Some(v) => max_age(v).map_or(true, |n| n < 86400),
        };
        if weak {
            fs.push(Finding::new("hsts", "warning", "Weak or missing HSTS.", url));
        }
    }

    if let Some(cookie) = header(&headers, "Set-Cookie") {
        let low = cookie.to_lowercase();
        if !low.contains("httponly") {
            fs.push(Finding::new("cookie-flags", "warning", "Cookie missing HttpOnly.", url));
        }
        if is_https && !low.contains("secure") {
            fs.push(Finding::new("cookie-flags", "warning", "Cookie missing Secure.", url));
        }
        if !low.contains("samesite") {
            fs.push(Finding::new("cookie-flags", "warning", "Cookie missing SameSite.", url));
        }
    }

    if let Some(acao) = header(&headers, "Access-Control-Allow-Origin") {
        if acao.trim() == "*" {
            fs.push(Finding::new("cors-wildcard", "warning", "CORS Access-Control-Allow-Origin is '*'.", url));
        }
    }

    if has_aws_key(body) || body.contains("-----BEGIN ") && body.contains("PRIVATE KEY-----") {
        fs.push(Finding::new("info-disclosure", "error", "Secret material in body.", url));
    }
    fs
}

fn has_aws_key(body: &str) -> bool {
    let bytes = body.as_bytes();
    for i in 0..bytes.len() {
        if body[i..].starts_with("AKIA") && i + 20 <= bytes.len() {
            let rest = &body[i + 4..i + 20];
            if rest.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

/// Scan a parsed JSON document: {"responses":[..]} | single record | array.
pub fn scan_input(data: &Value) -> Value {
    let mut fs = Vec::new();
    let records: Vec<Value> = if let Some(arr) = data.get("responses").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = data.as_array() {
        arr.clone()
    } else {
        vec![data.clone()]
    };
    for rec in &records {
        if rec.is_object() {
            fs.extend(run_passive_checks(rec));
        }
    }
    let findings: Vec<Value> = fs.iter().map(|f| f.to_json()).collect();
    json!({"tool": "dastlite", "score": findings.len(), "findings": findings})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ids(fs: &[Finding]) -> Vec<String> {
        fs.iter().map(|f| f.rule_id.clone()).collect()
    }

    #[test]
    fn missing_headers_https() {
        let fs = run_passive_checks(&json!({"url": "https://x/", "status": 200, "headers": {}}));
        let r = ids(&fs);
        for id in ["missing-csp", "missing-x-frame-options", "hsts"] {
            assert!(r.iter().any(|x| x == id), "{}", id);
        }
    }

    #[test]
    fn clean_response() {
        let fs = run_passive_checks(&json!({"url": "https://x/", "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=99999999"
        }}));
        assert!(fs.is_empty());
    }

    #[test]
    fn hsts_skipped_on_http() {
        let fs = run_passive_checks(&json!({"url": "http://x/", "headers": {}}));
        assert!(!ids(&fs).iter().any(|x| x == "hsts"));
    }

    #[test]
    fn cookie_flags() {
        let fs = run_passive_checks(&json!({"url": "https://x/", "headers": {"Set-Cookie": "a=b"}}));
        assert!(ids(&fs).iter().any(|x| x == "cookie-flags"));
    }

    #[test]
    fn cors_wildcard() {
        let fs = run_passive_checks(&json!({"url": "https://x/", "headers": {"Access-Control-Allow-Origin": "*"}}));
        assert!(ids(&fs).iter().any(|x| x == "cors-wildcard"));
    }

    #[test]
    fn info_disclosure() {
        let fs = run_passive_checks(&json!({"url": "https://x/", "body": "AKIAIOSFODNN7EXAMPLE"}));
        let f = fs.iter().find(|f| f.rule_id == "info-disclosure").unwrap();
        assert_eq!(f.level, "error");
    }

    #[test]
    fn case_insensitive() {
        let fs = run_passive_checks(&json!({"url": "https://x/", "headers": {"content-security-policy": "x"}}));
        assert!(!ids(&fs).iter().any(|x| x == "missing-csp"));
    }

    #[test]
    fn scan_input_responses() {
        let out = scan_input(&json!({"responses": [{"url": "https://x/", "headers": {}}]}));
        assert_eq!(out["tool"], "dastlite");
        assert!(out["score"].as_u64().unwrap() > 0);
    }
}
