package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// =============================================================================
// CONFIGURATION SCHEMA
// =============================================================================

// Config represents the complete DASTLite configuration.
type Config struct {
	Version    string        `yaml:"version" json:"version"`
	Targets    []Target      `yaml:"targets" json:"targets"`
	Auth       *AuthConfig   `yaml:"auth" json:"auth,omitempty"`
	Ruleset    RulesetConfig `yaml:"ruleset" json:"ruleset"`
	Output     OutputConfig  `yaml:"output" json:"output"`
	Env        EnvConfig     `yaml:"env" json:"env"`
	Retry      RetryConfig   `yaml:"retry" json:"retry"`
}

// Target defines a URL to scan.
type Target struct {
	URL         string    `yaml:"url" json:"url"`
	Method      string    `yaml:"method,omitempty" json:"method,omitempty"`
	Headers     []string  `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body        string    `yaml:"body,omitempty" json:"body,omitempty"`
	Timeout     int       `yaml:"timeout,omitempty" json:"timeout,omitempty"` // seconds
	MaxRetries  int       `yaml:"max_retries,omitempty" json:"max_retries,omitempty"`
	FollowRedirects bool   `yaml:"follow_redirects,omitempty" json:"follow_redirects,omitempty"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	Type         string            `yaml:"type,omitempty" json:"type,omitempty"` // "basic", "oauth2", "bearer", "session"
	Username     string            `yaml:"username,omitempty" json:"username,omitempty"`
	Password     string            `yaml:"password,omitempty" json:"password,omitempty"`
	Token        string            `yaml:"token,omitempty" json:"token,omitempty"`
	OAuth2       *OAuth2Config     `yaml:"oauth2,omitempty" json:"oauth2,omitempty"`
	Session      *SessionConfig    `yaml:"session,omitempty" json:"session,omitempty"`
	Headers      []string          `yaml:"headers,omitempty" json:"headers,omitempty"` // Additional auth headers
	CookieJar    bool              `yaml:"cookie_jar,omitempty" json:"cookie_jar,omitempty"`
}

// OAuth2Config for OAuth 2.0 flow.
type OAuth2Config struct {
	ClientID     string   `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	ClientSecret string   `yaml:"client_secret,omitempty" json:"client_secret,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	TokenURL     string   `yaml:"token_url,omitempty" json:"token_url,omitempty"`
}

// SessionConfig for session-based auth.
type SessionConfig struct {
	CookieName    string `yaml:"cookie_name,omitempty" json:"cookie_name,omitempty"`
	LoginURL      string `yaml:"login_url,omitempty" json:"login_url,omitempty"`
	LoginForm     string `yaml:"login_form,omitempty" json:"login_form,omitempty"` // selector or xpath
}

// RulesetConfig defines what scans to run.
type RulesetConfig struct {
	Name    string   `yaml:"name,omitempty" json:"name,omitempty"`
	Version string   `yaml:"version,omitempty" json:"version,omitempty"`
	Enabled  bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Rules   []string `yaml:"rules,omitempty" json:"rules,omitempty"` // rule IDs or patterns
	Categories []CategoryConfig `yaml:"categories,omitempty" json:"categories,omitempty"`
}

// CategoryConfig for grouping rules.
type CategoryConfig struct {
	Name       string  `yaml:"name,omitempty" json:"name,omitempty"`
	Enabled    bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Priority   int     `yaml:"priority,omitempty" json:"priority,omitempty"`
	RuleIDs    []string `yaml:"rule_ids,omitempty" json:"rule_ids,omitempty"`
}

// OutputConfig defines output settings.
type OutputConfig struct {
	Format       string  `yaml:"format,omitempty" json:"format,omitempty"` // "sarif", "json", "html"
	Version      int     `yaml:"version,omitempty" json:"version,omitempty"`
	OutputDir    string  `yaml:"output_dir,omitempty" json:"output_dir,omitempty"`
	Filename     string  `yaml:"filename,omitempty" json:"filename,omitempty"`
	Verbose      bool    `yaml:"verbose,omitempty" json:"verbose,omitempty"`
	IncludeRaw   bool    `yaml:"include_raw,omitempty" json:"include_raw,omitempty"`
	SarifVersion string  `yaml:"sarif_version,omitempty" json:"sarif_version,omitempty"` // "2.1", "2.6"
}

// EnvConfig for environment variable handling.
type EnvConfig struct {
	Substitute bool   `yaml:"substitute,omitempty" json:"substitute,omitempty"`
	Prefix     string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
}

// RetryConfig for retry behavior.
type RetryConfig struct {
	Enabled        bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MaxAttempts     int     `yaml:"max_attempts,omitempty" json:"max_attempts,omitempty"`
	InitialDelay    int     `yaml:"initial_delay,omitempty" json:"initial_delay,omitempty"` // seconds
	BackoffFactor   float64 `yaml:"backoff_factor,omitempty" json:"backoff_factor,omitempty"`
	MaxDelay        int     `yaml:"max_delay,omitempty" json:"max_delay,omitempty"` // seconds
}

// =============================================================================
// PARSER IMPLEMENTATION
// =============================================================================

const (
	defaultConfigPath = ".dastlite.yaml"
	sarifVersion26    = "2.6"
)

// Parser handles config file reading and parsing.
type Parser struct {
	config   *Config
	loadedAt time.Time
}

// NewParser creates a new parser instance.
func NewParser() *Parser {
	return &Parser{
		loadedAt: time.Now(),
	}
}

// Load reads the config file from disk and parses it.
func (p *Parser) Load(ctx context.Context, path string) error {
	if path == "" {
		path = defaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	p.config = &Config{}
	
	// Parse YAML with custom unmarshaling for environment substitution
	err = p.unmarshalWithEnv(ctx, data, p.config)
	if err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}

	p.loadedAt = time.Now()
	return nil
}

// LoadFromBytes parses config from raw bytes.
func (p *Parser) LoadFromBytes(ctx context.Context, data []byte) error {
	p.config = &Config{}
	err := p.unmarshalWithEnv(ctx, data, p.config)
	if err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}
	p.loadedAt = time.Now()
	return nil
}

// unmarshalWithEnv handles environment variable substitution before parsing.
func (p *Parser) unmarshalWithEnv(ctx context.Context, data []byte, cfg *Config) error {
	if !cfg.Env.Substitute {
		return yaml.Unmarshal(data, cfg)
	}

	// Substitute environment variables in the YAML content
	substituted := substituteEnvVars(string(data), cfg.Env.Prefix)
	
	// Parse the substituted content
	return yaml.Unmarshal([]byte(substituted), cfg)
}

// substituteEnvVars replaces ${VAR_NAME} or ${PREFIX_VAR_NAME} patterns with env values.
func substituteEnvVars(content string, prefix string) string {
	var result strings.Builder
	
	for {
		idx := strings.Index(content, "${")
		if idx == -1 {
			result.WriteString(content)
			break
		}

		// Find closing brace
		endIdx := strings.Index(content[idx:], "}")
		if endIdx == -1 {
			result.WriteString(content)
			break
		}

		varName := content[idx+2 : idx+endIdx]
		
		// Check for prefix
		fullVarName := varName
		if prefix != "" && !strings.HasPrefix(varName, prefix) {
			fullVarName = prefix + "_" + varName
		}

		value := os.Getenv(fullVarName)
		if value == "" {
			result.WriteString(content[:idx] + "${" + fullVarName + "}")
		} else {
			result.WriteString(content[:idx] + value)
		}

		content = content[idx+endIdx+1:]
	}

	return result.String()
}

// =============================================================================
// VALIDATION
// =============================================================================

// Validate checks the config for required fields and consistency.
func (p *Parser) Validate(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("config not loaded")
	}

	var issues []string

	// Check version
	if p.config.Version == "" {
		issues = append(issues, "warning: no config version specified (recommended)")
	}

	// Check targets
	if len(p.config.Targets) == 0 {
		return fmt.Errorf("at least one target URL is required")
	}

	for i, t := range p.config.Targets {
		if !strings.Contains(t.URL, "://") && !strings.HasPrefix(t.URL, "/") {
			issues = append(issues, fmt.Sprintf("target[%d]: URL should be absolute or start with /", i))
		}
		if t.Timeout <= 0 {
			t.Timeout = 30 // default 30s
		}
		if t.MaxRetries < 0 {
			t.MaxRetries = 3 // default 3 retries
		}
	}

	// Check auth configuration
	if p.config.Auth != nil {
		switch p.config.Auth.Type {
		case "basic":
			if p.config.Auth.Username == "" || p.config.Auth.Password == "" {
				issues = append(issues, "auth.basic: both username and password required")
			}
		case "bearer":
			if p.config.Auth.Token == "" {
				issues = append(issues, "auth.bearer: token required for bearer auth")
			}
		case "oauth2":
			if p.config.Auth.OAuth2 != nil && p.config.Auth.OAuth2.ClientID == "" {
				issues = append(issues, "auth.oauth2: client_id required")
			}
		case "session":
			if p.config.Auth.Session != nil {
				if p.config.Auth.Session.LoginURL == "" {
					issues = append(issues, "auth.session: login_url required for session auth")
				}
			}
		}

		if len(p.config.Auth.Headers) > 0 {
			for _, h := range p.config.Auth.Headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) != 2 || parts[0] == "" {
					issues = append(issues, fmt.Sprintf("auth.headers: invalid header format '%s'", h))
				}
			}
		}
	}

	// Check ruleset
	if p.config.Ruleset.Name == "" {
		p.config.Ruleset.Name = "default"
	}
	if !p.config.Ruleset.Enabled && len(p.config.Ruleset.Rules) > 0 {
		issues = append(issues, "warning: ruleset disabled but rules defined")
	}

	// Check output config
	if p.config.Output.Format == "" {
		p.config.Output.Format = "sarif"
	}
	if p.config.Output.Version < 1 || p.config.Output.Version > 3 {
		p.config.Output.Version = 26
	}
	if p.config.Output.SarifVersion == "" {
		p.config.Output.SarifVersion = sarifVersion26
	}

	// Check retry config
	if !p.config.Retry.Enabled && p.config.Retry.MaxAttempts > 1 {
		p.config.Retry.MaxAttempts = 1
	}

	if len(issues) > 0 {
		for _, issue := range issues {
			fmt.Fprintf(os.Stderr, "config: %s\n", issue)
		}
	}

	return nil
}

// =============================================================================
// ACCESSORS
// =============================================================================

// GetTargets returns the list of targets.
func (p *Parser) GetTargets() []Target {
	if p.config == nil {
		return nil
	}
	return p.config.Targets
}

// GetAuth returns the authentication configuration.
func (p *Parser) GetAuth() *AuthConfig {
	if p.config == nil {
		return &AuthConfig{}
	}
	return p.config.Auth
}

// GetRuleset returns the ruleset configuration.
func (p *Parser) GetRuleset() RulesetConfig {
	if p.config == nil {
		return RulesetConfig{Enabled: true, Name: "default"}
	}
	return p.config.Ruleset
}

// GetOutput returns the output configuration.
func (p *Parser) GetOutput() OutputConfig {
	if p.config == nil {
		return OutputConfig{Format: "sarif", Version: 26}
	}
	return p.config.Output
}

// GetRetry returns the retry configuration.
func (p *Parser) GetRetry() RetryConfig {
	if p.config == nil {
		return RetryConfig{Enabled: true, MaxAttempts: 1}
	}
	return p.config.Retry
}

// =============================================================================
// SERIALIZATION
// =============================================================================

// Marshal returns the config as YAML bytes.
func (p *Parser) Marshal() ([]byte, error) {
	if p.config == nil {
		return []byte{}, fmt.Errorf("config not loaded")
	}
	
	// Use a temporary struct to avoid infinite recursion with custom types
	temp := &Config{
		Version:    p.config.Version,
		Targets:    p.config.Targets,
		Auth:       p.config.Auth,
		Ruleset:    p.config.Ruleset,
		Output:     p.config.Output,
		Env:        p.config.Env,
		Retry:      p.config.Retry,
	}

	return yaml.Marshal(temp)
}

// MarshalJSON returns the config as JSON bytes.
func (p *Parser) MarshalJSON() ([]byte, error) {
	if p.config == nil {
		return []byte{}, fmt.Errorf("config not loaded")
	}
	
	temp := &Config{
		Version:    p.config.Version,
		Targets:    p.config.Targets,
		Auth:       p.config.Auth,
		Ruleset:    p.config.Ruleset,
		Output:     p.config.Output,
		Env:        p.config.Env,
		Retry:      p.config.Retry,
	}

	return json.Marshal(temp)
}

// =============================================================================
// DEMO / ENTRY POINT
// =============================================================================

func main() {
	ctx := context.Background()
	parser := NewParser()

	// Try to load from default path first
	if err := parser.Load(ctx, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Validate the configuration
	if err := parser.Validate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
		os.Exit(1)
	}

	// Print parsed config as JSON for demo purposes
	jsonBytes, _ := parser.MarshalJSON()
	fmt.Println(string(jsonBytes))

	// Demo with environment variable substitution
	fmt.Println("\n--- Environment Variable Substitution Demo ---")
	
	testYAML := `
version: "1.0"
targets:
  - url: https://example.com/api
    headers:
      - Authorization: ${API_TOKEN}
auth:
  type: bearer
  token: ${API_TOKEN}
env:
  substitute: true
`

	// Parse with substitution enabled
	parser2 := NewParser()
	err = parser2.LoadFromBytes(ctx, []byte(testYAML))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing test YAML: %v\n", err)
		os.Exit(1)
	}

	// Set environment variable for demo
	os.Setenv("API_TOKEN", "Bearer demo-token-12345")

	// Re-parse with substitution
	parser3 := NewParser()
	err = parser3.LoadFromBytes(ctx, []byte(testYAML))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing test YAML: %v\n", err)
		os.Exit(1)
	}

	auth := parser3.GetAuth()
	fmt.Printf("Parsed auth token after substitution: %