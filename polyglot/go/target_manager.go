//go:build go1.20
// +build go1.20

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// CONFIGURATION TYPES (config-as-code ready)
// =============================================================================

type AuthConfig struct {
	Type         string   `json:"type"`          // "basic", "bearer", "cookie", "header"
	BasicUser    string   `json:"basic_user,omitempty"`
	BasicPass    string   `json:"basic_pass,omitempty"`
	BearerToken  string   `json:"bearer_token,omitempty"`
	CookieName   string   `json:"cookie_name,omitempty"`
	CookieValue  string   `json:"cookie_value,omitempty"`
	HeaderKey    string   `json:"header_key,omitempty"`
	HeaderValue  string   `json:"header_value,omitempty"`
	TLSClientCerts []string `json:"tls_client_certs,omitempty"` // PEM paths
}

type TargetConfig struct {
	Name       string        `json:"name"`           // human-readable identifier
	URLs       []string      `json:"urls"`           // list of base URLs to crawl
	Auth       AuthConfig    `json:"auth,omitempty"` // authentication configuration
	Timeout    time.Duration `json:"timeout,omitempty"` // HTTP timeout per request
	MaxDepth   int           `json:"max_depth,omitempty"` // max redirects/follows
}

type TargetManagerConfig struct {
	Targets     []TargetConfig `json:"targets"`
	DefaultAuth AuthConfig     `json:"default_auth,omitempty"` // fallback auth for all targets
	GlobalTimeout time.Duration `json:"global_timeout,omitempty"`
}

// =============================================================================
// CORE TYPES
// =============================================================================

type Target struct {
	ID         string
	Config     TargetConfig
	ResolvedURLs []string // normalized, deduplicated URLs
	Auth       AuthConfig
	HTTPClient *http.Client
	LastError  error
}

type ManagerState int

const (
	StateNew    ManagerState = iota
	StateValidated
	StateActive
)

// =============================================================================
// TARGET MANAGER IMPLEMENTATION
// =============================================================================

type TargetManager struct {
	config     TargetManagerConfig
	state      ManagerState
	mu         sync.RWMutex
	clients    map[string]*http.Client // cache by target ID
	validated  bool
}

func NewTargetManager(cfg TargetManagerConfig) *TargetManager {
	if len(cfg.Targets) == 0 {
		cfg.Targets = []TargetConfig{}
	}
	return &TargetManager{
		config:    cfg,
		state:     StateNew,
		clients:   make(map[string]*http.Client),
	}
}

// LoadFromJSON reads config from a file path.
func (m *TargetManager) LoadFromJSON(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	var cfg TargetManagerConfig
	if err = json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}
	m.config = cfg
	m.state = StateNew
	return nil
}

// =============================================================================
// VALIDATION PHASE
// =============================================================================

func (m *TransitionToValidated() error {
	if m.state != StateNew && m.state != StateActive {
		return fmt.Errorf("manager already in state: %v", m.state)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.validated {
		return nil // already validated
	}

	var errs []string

	// 1. Validate target list is non-empty
	if len(m.config.Targets) == 0 {
		errs = append(errs, "no targets defined")
	}

	// 2. Resolve and normalize all URLs for each target
	for i, tc := range m.config.Targets {
		targetID := fmt.Sprintf("target-%d", i)

		// Build auth config (merge default with per-target override)
		auth := m.config.DefaultAuth
		if !tc.Auth.Type == "" {
			auth = tc.Auth
		}

		// Resolve base URLs
		resolved, err := m.resolveURLs(tc.URLs, targetID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("target %q URL resolution: %v", tc.Name, err))
			continue
		}

		m.config.Targets[i].ResolvedURLs = resolved
	}

	// 3. Report validation errors if any
	if len(errs) > 0 {
		return fmt.Errorf("validation failed:\n%s", strings.Join(errs, "\n"))
	}

	m.validated = true
	m.state = StateValidated
	return nil
}

func (m *TargetManager) resolveURLs(rawURLs []string, targetID string) ([]string, error) {
	var resolved []string
	seen := make(map[string]struct{})

	for _, raw := range rawURLs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing URL %q: %w", raw, err)
		}

		// Normalize and dedupe
		norm := u.String()
		if _, exists := seen[norm]; !exists {
			resolved = append(resolved, norm)
			seen[norm] = struct{}{}
		}
	}

	return resolved, nil
}

// =============================================================================
// HTTP CLIENT FACTORY
// =============================================================================

func (m *TargetManager) newHTTPClient(targetID string, auth AuthConfig, timeout time.Duration) (*http.Client, error) {
	var transport http.RoundTripper = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost:  256,
		IdleConnTimeout:      90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		TLSServerName:        "", // set per-target if needed
	}

	if len(auth.TLSClientCerts) > 0 {
		certPool := &tls.CertificatePool{}
		for _, certPath := range auth.TLSClientCerts {
			cert, err := tls.LoadX509KeyPair(certPath, filepath.Base(certPath))
			if err != nil {
				return nil, fmt.Errorf("loading client cert %q: %w", certPath, err)
			}
			certPool.AddCert(cert)
		}
		transport.TLSClientConfig = &tls.Config{
			Certificates: certPool.Certs(),
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return client, nil
}

// =============================================================================
// CONNECTIVITY CHECK
// =============================================================================

func (m *TargetManager) CheckConnectivity(ctx context.Context) error {
	if m.state != StateValidated {
		return fmt.Errorf("manager not yet validated")
	}

	var failures []string

	for _, tc := range m.config.Targets {
		targetID := fmt.Sprintf("target-%d", tc.ID)

		auth := tc.Auth
		if auth.Type == "" {
			auth = m.config.DefaultAuth
		}

		client, err := m.newHTTPClient(targetID, auth, tc.Timeout)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", targetID, err))
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "GET", tc.ResolvedURLs[0], nil)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s request creation: %v", targetID, err))
			continue
		}

		m.applyAuth(req, auth)

		resp, err := client.Do(req)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s HTTP error: %v", targetID, err))
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			failures = append(failures, fmt.Sprintf(
				"%s got status %d (expected 2xx): %s",
				targetID, resp.StatusCode, resp.Status))
		} else {
			resp.Body.Close() // cleanup
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("connectivity check failed:\n%s", strings.Join(failures, "\n"))
	}

	return nil
}

func (m *TargetManager) applyAuth(req *http.Request, auth AuthConfig) {
	switch auth.Type {
	case "basic":
		req.SetBasicAuth(auth.BasicUser, auth.BasicPass)
	case "bearer":
		if auth.BearerToken != "" {
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth.BearerToken))
		}
	case "cookie":
		if auth.CookieName != "" && auth.CookieValue != "" {
			req.AddCookie(&http.Cookie{
				Name:  auth.CookieName,
				Value: auth.CookieValue,
			})
		}
	case "header":
		if auth.HeaderKey != "" && auth.HeaderValue != "" {
			req.Header.Set(auth.HeaderKey, auth.HeaderValue)
		}
	}
}

// =============================================================================
// ACTIVE SCANNING PHASE
// =============================================================================

type ScanRule struct {
	Name         string
	Pattern      string // regex or literal pattern to match against response
	Method       string // "GET", "POST", etc.
	Path         string // URL path template (e.g., "/api/v1/users")
	Headers      map[string]string
	Body         string
	ExpectedCode int
}

type ScanResult struct {
	RuleName    string
	URL         string
	ResponseURL string
	StatusCode  int
	Matched     bool
	MatchData   []string // captured groups if regex matched
	Body        string
	Error       error
	Timestamp   time.Time
}

func (m *TargetManager) RunActiveScans(ctx context.Context, ruleset []ScanRule) ([]ScanResult, error) {
	if m.state != StateValidated {
		return nil, fmt.Errorf("manager not validated")
	}

	var results []ScanResult

	for _, tc := range m.config.Targets {
		targetID := fmt.Sprintf("target-%d", tc.ID)

		auth := tc.Auth
		if auth.Type == "" {
			auth = m.config.DefaultAuth
		}

		client, err := m.newHTTPClient(targetID, auth, tc.Timeout)
		if err != nil {
			return results, fmt.Errorf("%s client creation: %w", targetID, err)
		}

		for _, rule := range ruleset {
			for _, baseURL := range tc.ResolvedURLs {
				fullURL := buildFullURL(baseURL, rule.Path)
				if fullURL == "" {
					continue
				}

				req, err := http.NewRequestWithContext(ctx, rule.Method, fullURL, strings.NewReader(rule.Body))
				if err != nil {
					results = append(results, ScanResult{
						RuleName:  rule.Name,
						URL:       baseURL,
						Error:     fmt.Errorf("request creation: %w", err),
						Timestamp: time.Now(),
					})
					continue
				}

				m.applyAuth(req, auth)

				resp, err := client.Do(req)
				if err != nil {
					results = append(results, ScanResult{
						RuleName:  rule.Name,
						URL:       baseURL,
						Error:     fmt.Errorf("HTTP request: %w", err),
						Timestamp: time.Now(),
					})
					continue
				}

				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
				resp.Body.Close()

				results = append(results, ScanResult{
					RuleName:    rule.Name,
					URL:          baseURL,
					ResponseURL: resp.Header.Get("Location"),
					StatusCode:   resp.StatusCode,
					Body:         string(bodyBytes),
					Timestamp:    time.Now(),
				})

				if rule.ExpectedCode != 0 && resp.StatusCode == rule.ExpectedCode {
					results[len(results)-1].Matched = true
				}

				if matched := m.matchPattern(string(bodyBytes), rule.Pattern); matched {
					results[len(results)-1].Matched = true
					results[len(results)-1].MatchData = matched
				}
			}
		}
	}

	return results, nil
}

func (m *TargetManager) matchPattern(body string, pattern string) []string {
	if pattern == "" || body == "" {
		return nil
	}

	// Simple regex matching using strings.Contains for literals
	// For full regex support, would use regexp package
	if strings.Contains(pattern, `(`) && strings.Contains(pattern, `)`) {
		// Basic capture group detection (placeholder for real impl)
		return []string{body[:min(100, len(body))] + "..."} // truncated sample
	}

	if strings.Contains(pattern, ".") || strings.Contains(pattern, "*") {
		// Wildcard/literal match
		idx := strings.Index(body, pattern)
		if idx >= 0 {
			return []string{body[idx : idx+min(100, len(body)-idx)] + "..."}
		}
	}

	return nil
}

func buildFullURL(base string, path string) string {
	if base == "" || path == "" {
		return ""
	}
	if strings.HasSuffix(base, "/") && !strings.HasPrefix(path, "/") {
		return base + "/" + path
	}
	return base + path
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// DEDUPLICATION & REPORTING
// =============================================================================

type DedupResult struct {
	URLs        []string
	Duplicates  map[string][]int // URL -> list of duplicate indices
	Total       int
	UniqueCount int
}

func (m *TargetManager) DeduplicateResults(results []ScanResult, urlField string) *DedupResult {
	if len(results) == 0 {
		return &DedupResult{URLs: nil, Duplicates: make(map[string][]int), Total: 0, UniqueCount: 0}
	}

	type indexed struct {
		index int
		url   string
		data  []byte // for content-based dedupe if needed
	}

	var indexed []indexed
	for i, r := range results {
		u := ""
		if urlField == "URL" {
			u = r.URL
		} else if urlField == "ResponseURL" {
			u = r.ResponseURL
		}
		indexed = append(indexed, indexed{index: i, url: u, data: []byte(r.Body)})
	}

	if len(indexed) == 0 {
		return &DedupResult{URLs: nil, Duplicates: make(map[string][]int), Total: 0, UniqueCount: 0}
	}

	// Group by URL
	urlMap := make(map[string][]indexed)
	for _, idx := range indexed {
		if idx.url != "" {
			urlMap[idx.url] = append(urlMap[idx.url], idx)
		}
	}

	var unique []string
	duplicates := make(map[string][]int)

	for u, items := range urlMap {
		if len(items) > 1 {
			// Found duplicates
			idxList := make([]int, len(items))
			for i, item := range items {
				idxList[i] = item.index
			}
			duplicates[u] = idxList
		} else {
			unique = append(unique, u)
		}
	}

	return &DedupResult{
		URLs:        unique,
		Duplicates:  duplicates,
		Total:       len(results),
		UniqueCount: len(unique),
	}
}

// =============================================================================
// ENTRY POINT / DEMO
// =============================================================================

func main() {
	// Sample configuration (config-as-code pattern)
	cfg := TargetManagerConfig{
		Targets: []TargetConfig{
			{
				Name:   "API Gateway",
				URLs:   []string{"https://api.example.com/v1"},
				Auth: AuthConfig{
					Type:     "bearer",
					BearerToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
				},
				Timeout: 30 * time.Second,
			},
		},
		DefaultAuth: AuthConfig{
			Type:     "basic",
			BasicUser: "admin",
			BasicPass: "secret123",
		},
		GlobalTimeout