mod polyglot {
    pub mod rust {
        use std::collections::{HashMap, HashSet};
        use std::env;
        use std::fs;
        use std::path::{Path, PathBuf};
        use std::time::Duration;

        // =====================================================================
        // ERRORS & RESULT TYPES
        // =====================================================================

        #[derive(Debug)]
        pub enum ConfigError {
            Io(std::io::Error),
            Serde(serde_json::Error),
            Validation(String),
            MissingField(String),
            InvalidUrl(String),
            InvalidAuth(String),
            DuplicateProfile(String),
            EmptyConfig,
        }

        impl std::fmt::Display for ConfigError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    ConfigError::Io(e) => write!(f, "IO error: {}", e),
                    ConfigError::Serde(e) => write!(f, "JSON parse error: {}", e),
                    ConfigError::Validation(msg) => write!(f, "Validation failed: {}", msg),
                    ConfigError::MissingField(field) => {
                        write!(f, "Required field missing: {}", field)
                    }
                    ConfigError::InvalidUrl(url) => write!(f, "Invalid URL: {}", url),
                    ConfigError::InvalidAuth(msg) => write!(f, "Invalid auth config: {}", msg),
                    ConfigError::DuplicateProfile(name) => {
                        write!(f, "Duplicate profile name: {}", name)
                    }
                    ConfigError::EmptyConfig => write!(f, "Configuration is empty"),
                }
            }
        }

        impl std::error::Error for ConfigError {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    ConfigError::Io(e) => Some(e),
                    ConfigError::Serde(e) => Some(e),
                    _ => None,
                }
            }
        }

        pub type Result<T> = std::result::Result<T, ConfigError>;

        // =====================================================================
        // CONFIGURATION DATA MODELS
        // =====================================================================

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct Config {
            /// Global scan options
            pub global: Option<GlobalOptions>,
            
            /// Target profiles (can be multiple for multi-target runs)
            pub profiles: Vec<Profile>,
            
            /// Curated rule set to apply
            pub ruleset: Option<RuleSetConfig>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct GlobalOptions {
            pub timeout: Option<u64>,           // Default timeout in seconds
            pub retries: Option<u16>,            // Retry count per request
            pub user_agent: Option<String>,      // Custom UA header
            pub headers: HashMap<String, String>, // Additional HTTP headers
        }

        #[derive(Debug, Clone, serde::Deserialize)]
        pub struct Profile {
            /// Unique identifier for this profile
            pub name: String,
            
            /// Target URL(s) - can be comma-separated or array
            #[serde(default, rename = "url")]
            pub urls: Vec<String>,
            
            /// Authentication configuration
            pub auth: Option<AuthConfig>,
            
            /// Scope and filtering options
            pub scope: Option<ScopeOptions>,
            
            /// Rate limiting / throttling
            pub rate_limit: Option<RateLimitOptions>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct AuthConfig {
            /// Type of authentication (basic, bearer, oauth2, cookie)
            pub kind: AuthKind,
            
            /// Basic auth credentials
            #[serde(default)]
            pub basic: Option<BasicAuth>,
            
            /// Bearer token for API auth
            #[serde(default)]
            pub bearer: Option<BearerToken>,
            
            /// OAuth2 configuration
            #[serde(default)]
            pub oauth2: Option<OAuth2Config>,
            
            /// Cookie-based auth (for session management)
            #[serde(default)]
            pub cookie: Option<SessionCookie>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub enum AuthKind {
            #[default]
            Basic,
            Bearer,
            OAuth2,
            Cookie,
            Header,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct BasicAuth {
            pub username: String,
            pub password: String,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct BearerToken {
            pub token: String,
            /// Optional scopes for OAuth2 bearer tokens
            #[serde(default)]
            pub scopes: Option<Vec<String>>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct OAuth2Config {
            pub client_id: String,
            pub client_secret: String,
            pub token_url: String,
            pub auth_url: String,
            
            /// Authorization code flow settings
            #[serde(default)]
            pub authorization_code: Option<AuthorizationCode>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct AuthorizationCode {
            pub redirect_uri: String,
            pub scopes: Vec<String>,
            pub state: String,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct SessionCookie {
            /// Cookie name (e.g., "session", "auth_token")
            pub name: String,
            
            /// Optional cookie value override
            #[serde(default)]
            pub value: Option<String>,
            
            /// Path restriction for the cookie
            #[serde(default)]
            pub path: Option<String>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct ScopeOptions {
            /// Include only these paths (prefix matching)
            #[serde(default)]
            pub include: Vec<String>,
            
            /// Exclude these paths (prefix matching)
            #[serde(default)]
            pub exclude: Vec<String>,
            
            /// Depth limit for crawling
            #[serde(default)]
            pub depth: Option<u32>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct RateLimitOptions {
            /// Requests per second limit
            #[serde(default)]
            pub rps_limit: Option<f64>,
            
            /// Burst size for rate limiting
            #[serde(default)]
            pub burst_size: Option<u32>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct RuleSetConfig {
            /// List of rule IDs to enable
            #[serde(default)]
            pub enabled_rules: Vec<String>,
            
            /// Severity threshold (info, low, medium, high, critical)
            #[serde(default)]
            pub severity_threshold: Option<SeverityLevel>,
            
            /// Rule-specific overrides
            #[serde(default)]
            pub rule_overrides: HashMap<String, RuleOverride>,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub enum SeverityLevel {
            Info,
            Low,
            #[default]
            Medium,
            High,
            Critical,
        }

        #[derive(Debug, Clone, Default, serde::Deserialize)]
        pub struct RuleOverride {
            /// Enable/disable specific rule
            #[serde(default)]
            pub enabled: Option<bool>,
            
            /// Custom severity override
            #[serde(default)]
            pub severity: Option<SeverityLevel>,
            
            /// Additional parameters for the rule
            #[serde(default)]
            pub params: HashMap<String, serde_json::Value>,
        }

        // =====================================================================
        // PARSER IMPLEMENTATION
        // =====================================================================

        impl Config {
            /// Creates a new config with defaults.
            pub fn new() -> Self {
                Self {
                    global: Some(GlobalOptions::default()),
                    profiles: Vec::new(),
                    ruleset: Some(RuleSetConfig::default()),
                }
            }

            /// Validates the configuration and returns any issues found.
            pub fn validate(&self) -> Result<Vec<String>> {
                let mut errors = Vec::new();

                // Check for empty profiles
                if self.profiles.is_empty() {
                    errors.push("At least one profile must be defined".to_string());
                }

                // Validate each profile
                let mut seen_names = HashSet::new();
                for (idx, profile) in self.profiles.iter().enumerate() {
                    if !seen_names.insert(profile.name.clone()) {
                        errors.push(format!(
                            "Profile '{}' appears multiple times",
                            profile.name
                        ));
                    }

                    // Validate URLs
                    let mut valid_urls = 0;
                    for url in &profile.urls {
                        if let Err(e) = Self::validate_url(url) {
                            errors.push(format!("Profile '{}': {}", profile.name, e));
                        } else {
                            valid_urls += 1;
                        }
                    }

                    if valid_urls == 0 && !errors.iter().any(|e| e.contains(&format!("Profile '{}'", profile.name))) {
                        errors.push(format!(
                            "Profile '{}' has no valid URLs",
                            profile.name
                        ));
                    }

                    // Validate auth configuration
                    if let Some(ref auth) = profile.auth {
                        if let Err(e) = Self::validate_auth(auth, &profile.name) {
                            errors.push(e);
                        }
                    }

                    // Validate scope options
                    if let Some(ref scope) = profile.scope {
                        if let Err(e) = Self::validate_scope(scope, &profile.name) {
                            errors.push(e);
                        }
                    }
                }

                // Check for empty config
                if self.profiles.is_empty() && self.ruleset.is_none() {
                    errors.push("No profiles or ruleset defined".to_string());
                }

                Ok(errors)
            }

            /// Validates a single URL string.
            fn validate_url(url: &str) -> Result<()> {
                if url.trim().is_empty() {
                    return Err(ConfigError::InvalidUrl("Empty URL".to_string()));
                }

                // Basic URL validation without external dependencies
                let trimmed = url.trim();
                
                // Check for scheme
                if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
                    return Err(ConfigError::InvalidUrl(format!(
                        "Missing scheme (http:// or https://): {}",
                        trimmed
                    )));
                }

                Ok(())
            }

            /// Validates authentication configuration.
            fn validate_auth(auth: &AuthConfig, profile_name: &str) -> Result<()> {
                match &auth.kind {
                    AuthKind::Basic => {
                        if auth.basic.is_none() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': Basic auth selected but no credentials provided", profile_name),
                            ));
                        }
                        let basic = auth.basic.as_ref().unwrap();
                        if basic.username.trim().is_empty() || basic.password.trim().is_empty() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': Basic auth requires non-empty username and password", profile_name),
                            ));
                        }
                    }
                    AuthKind::Bearer => {
                        if auth.bearer.is_none() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': Bearer auth selected but no token provided", profile_name),
                            ));
                        }
                        let bearer = auth.bearer.as_ref().unwrap();
                        if bearer.token.trim().is_empty() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': Bearer token cannot be empty", profile_name),
                            ));
                        }
                    }
                    AuthKind::OAuth2 => {
                        if auth.oauth2.is_none() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': OAuth2 selected but no configuration provided", profile_name),
                            ));
                        }
                        let oauth = auth.oauth2.as_ref().unwrap();
                        
                        // Required fields for OAuth2
                        if oauth.client_id.trim().is_empty() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': OAuth2 client_id required", profile_name),
                            ));
                        }
                        if oauth.token_url.trim().is_empty() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': OAuth2 token_url required", profile_name),
                            ));
                        }
                    }
                    AuthKind::Cookie => {
                        if auth.cookie.is_none() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': Cookie auth selected but no configuration provided", profile_name),
                            ));
                        }
                        let cookie = auth.cookie.as_ref().unwrap();
                        if cookie.name.trim().is_empty() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': Cookie name required", profile_name),
                            ));
                        }
                    }
                    AuthKind::Header => {
                        // Header-based auth is minimal - just warn if no headers specified
                        if auth.basic.is_none() && auth.bearer.is_none() {
                            return Err(ConfigError::InvalidAuth(
                                format!("Profile '{}': Header auth selected but no credentials provided", profile_name),
                            ));
                        }
                    }
                }

                Ok(())
            }

            /// Validates scope options.
            fn validate_scope(scope: &ScopeOptions, profile_name: &str) -> Result<()> {
                // Validate include/exclude patterns
                for pattern in &scope.include {
                    if pattern.trim().is_empty() {
                        return Err(ConfigError::Validation(format!(
                            "Profile '{}': Include pattern cannot be empty",
                            profile_name
                        )));
                    }
                }

                for pattern in &scope.exclude {
                    if pattern.trim().is_empty() {
                        return Err(ConfigError::Validation(format!(
                            "Profile '{}': Exclude pattern cannot be empty",
                            profile_name
                        )));
                    }
                }

                // Validate depth
                let depth = scope.depth.unwrap_or(10);
                if depth > 50 {
                    return Err(ConfigError::Validation(format!(
                        "Profile '{}': Depth limit of {} is unusually high",
                        profile_name, depth
                    )));
                }

                Ok(())
            }

            /// Applies default values for missing optional fields.
            pub fn apply_defaults(&mut self) {
                // Apply global defaults
                if let Some(ref mut global) = self.global {
                    if global.timeout.is_none() {
                        global.timeout = Some(30); // 30 second default timeout
                    }
                    if global.retries.is_none() {
                        global.retries = Some(3);
                    }
                }

                // Apply profile defaults
                for profile in &mut self.profiles {
                    // Default scope options
                    if profile.scope.is_none() {
                        profile.scope = Some(ScopeOptions::default());
                    }

                    // Default rate limiting (10 req/s burst of 50)
                    if profile.rate_limit.is_none() {
                        profile.rate_limit = Some(RateLimitOptions {
                            rps_limit: Some(10.0),
                            burst_size: Some(50),
                        });
                    }

                    // Default auth (no auth by default, which is fine for public APIs)
                    if profile.auth.is_none() {
                        profile.auth = Some(AuthConfig::default());
                    }
                }

                // Apply ruleset defaults
                if let Some(ref mut ruleset) = self.ruleset {
                    // Default severity threshold
                    if ruleset.severity_threshold.is_none() {
                        ruleset.severity_threshold = Some(SeverityLevel::Medium);
                    }
                }
            }

            /// Merges environment variables into the config.
            pub fn merge_env(&mut self) -> Result<()> {
                // Environment variable interpolation for URLs and auth
                let env_prefix = "DASTLITE_";
                
                // Merge global options from env
                if let Some(ref mut global) = self.global {
                    if let Ok(val) = env::var(format!("{}_TIMEOUT", env_prefix)) {
                        if !val.trim().is_empty() {
                            global.timeout = Some(val.parse::<u64>().unwrap_or(30));
                        }
                    }

                    if let Ok(val) = env::var(format!("{}_RETRIES", env_prefix)) {
                        if !val.trim().is_empty() {
                            global.retries = Some(val.parse::<u16>().unwrap_or(3));
                        }
                    }
                }

                // Merge profile-specific env vars
                for (idx, profile) in self.profiles.iter_mut().enumerate()