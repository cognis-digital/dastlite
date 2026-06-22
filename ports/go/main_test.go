package main

import "testing"

func has(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestMissingHeadersHTTPS(t *testing.T) {
	fs := RunPassiveChecks(Target{URL: "https://x/", Status: 200, Headers: map[string]string{}})
	for _, id := range []string{"missing-csp", "missing-x-frame-options", "hsts"} {
		if !has(fs, id) {
			t.Fatalf("expected %s", id)
		}
	}
}

func TestCleanResponse(t *testing.T) {
	h := map[string]string{
		"Content-Security-Policy":   "default-src 'self'",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=99999999",
	}
	if fs := RunPassiveChecks(Target{URL: "https://x/", Status: 200, Headers: h}); len(fs) != 0 {
		t.Fatalf("expected no findings, got %d", len(fs))
	}
}

func TestHSTSSkippedOnHTTP(t *testing.T) {
	fs := RunPassiveChecks(Target{URL: "http://x/", Headers: map[string]string{}})
	if has(fs, "hsts") {
		t.Fatal("hsts should not fire on http")
	}
}

func TestCookieFlags(t *testing.T) {
	fs := RunPassiveChecks(Target{URL: "https://x/", Headers: map[string]string{"Set-Cookie": "a=b"}})
	if !has(fs, "cookie-flags") {
		t.Fatal("expected cookie-flags")
	}
}

func TestCorsWildcard(t *testing.T) {
	fs := RunPassiveChecks(Target{URL: "https://x/", Headers: map[string]string{"Access-Control-Allow-Origin": "*"}})
	if !has(fs, "cors-wildcard") {
		t.Fatal("expected cors-wildcard")
	}
}

func TestInfoDisclosure(t *testing.T) {
	fs := RunPassiveChecks(Target{URL: "https://x/", Body: "AKIAIOSFODNN7EXAMPLE"})
	if !has(fs, "info-disclosure") {
		t.Fatal("expected info-disclosure")
	}
}

func TestCaseInsensitiveHeaders(t *testing.T) {
	fs := RunPassiveChecks(Target{URL: "https://x/", Headers: map[string]string{"content-security-policy": "x"}})
	if has(fs, "missing-csp") {
		t.Fatal("lowercase CSP header should satisfy check")
	}
}

func TestScanInputResponses(t *testing.T) {
	out := ScanInput([]byte(`{"responses":[{"url":"https://x/","headers":{}}]}`))
	if out["tool"] != "dastlite" {
		t.Fatal("bad tool")
	}
	if out["score"].(int) == 0 {
		t.Fatal("expected findings")
	}
}
