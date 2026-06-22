// Go port of the dastlite PASSIVE core: analyze a captured HTTP response
// (status, headers, body) for security-header / cookie issues. Pure + offline,
// same rule IDs and JSON shape as the Python reference. Single binary, zero deps.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Target is a captured response.
type Target struct {
	URL     string            `json:"url"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Finding is one passive result.
type Finding struct {
	RuleID  string `json:"rule_id"`
	Level   string `json:"level"`
	Message string `json:"message"`
	URL     string `json:"url"`
}

func header(h map[string]string, name string) (string, bool) {
	low := strings.ToLower(name)
	for k, v := range h {
		if strings.ToLower(k) == low {
			return v, true
		}
	}
	return "", false
}

var maxAgeRe = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)
var awsRe = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
var keyRe = regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`)

// RunPassiveChecks returns all findings for one Target.
func RunPassiveChecks(t Target) []Finding {
	var fs []Finding
	isHTTPS := strings.HasPrefix(strings.ToLower(t.URL), "https://")

	sec := [][3]string{
		{"missing-csp", "Content-Security-Policy", "warning"},
		{"missing-x-content-type-options", "X-Content-Type-Options", "warning"},
		{"missing-x-frame-options", "X-Frame-Options", "warning"},
		{"missing-referrer-policy", "Referrer-Policy", "note"},
	}
	for _, s := range sec {
		if _, ok := header(t.Headers, s[1]); !ok {
			fs = append(fs, Finding{s[0], s[2], "Missing " + s[1] + " header.", t.URL})
		}
	}

	if isHTTPS {
		hsts, ok := header(t.Headers, "Strict-Transport-Security")
		weak := !ok
		if ok {
			m := maxAgeRe.FindStringSubmatch(hsts)
			if m == nil {
				weak = true
			} else if n, _ := strconv.Atoi(m[1]); n < 86400 {
				weak = true
			}
		}
		if weak {
			fs = append(fs, Finding{"hsts", "warning", "Weak or missing HSTS.", t.URL})
		}
	}

	if cookie, ok := header(t.Headers, "Set-Cookie"); ok {
		low := strings.ToLower(cookie)
		if !strings.Contains(low, "httponly") {
			fs = append(fs, Finding{"cookie-flags", "warning", "Cookie missing HttpOnly.", t.URL})
		}
		if isHTTPS && !strings.Contains(low, "secure") {
			fs = append(fs, Finding{"cookie-flags", "warning", "Cookie missing Secure.", t.URL})
		}
		if !strings.Contains(low, "samesite") {
			fs = append(fs, Finding{"cookie-flags", "warning", "Cookie missing SameSite.", t.URL})
		}
	}

	if acao, ok := header(t.Headers, "Access-Control-Allow-Origin"); ok && strings.TrimSpace(acao) == "*" {
		fs = append(fs, Finding{"cors-wildcard", "warning", "CORS Access-Control-Allow-Origin is '*'.", t.URL})
	}

	if awsRe.MatchString(t.Body) || keyRe.MatchString(t.Body) {
		fs = append(fs, Finding{"info-disclosure", "error", "Secret material in body.", t.URL})
	}
	return fs
}

// ScanInput accepts either {"responses":[...]} or a single record / array.
func ScanInput(raw []byte) map[string]any {
	var fs []Finding
	var asObj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asObj); err == nil {
		if r, ok := asObj["responses"]; ok {
			var recs []Target
			json.Unmarshal(r, &recs)
			for _, t := range recs {
				fs = append(fs, RunPassiveChecks(t)...)
			}
			return result(fs)
		}
		var one Target
		if err := json.Unmarshal(raw, &one); err == nil {
			return result(RunPassiveChecks(one))
		}
	}
	var recs []Target
	if err := json.Unmarshal(raw, &recs); err == nil {
		for _, t := range recs {
			fs = append(fs, RunPassiveChecks(t)...)
		}
	}
	return result(fs)
}

func result(fs []Finding) map[string]any {
	return map[string]any{"tool": "dastlite", "findings": fs, "score": len(fs)}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dastlite <capture.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	b, _ := json.MarshalIndent(ScanInput(raw), "", "  ")
	fmt.Println(string(b))
}
