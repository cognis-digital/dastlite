use std::fmt;
use std::path::{Path, PathBuf};
use url::Url;

/// Error types for target management operations.
#[derive(Debug)]
pub enum TargetError {
    /// Invalid URL format or resolution failure.
    UrlParse(Url),
    
    /// Duplicate target detected (same base + path).
    Duplicate(String),
    
    /// Relative URL without a resolved base.
    RelativeWithoutBase(String, String),
    
    /// IO error during file operations.
    Io(std::io::Error),
    
    /// Invalid configuration format.
    Config(serde_json::Error),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UrlParse(url) => write!(f, "URL parse error: {}", url),
            Self::Duplicate(s) => write!(f, "Duplicate target: {}", s),
            Self::RelativeWithoutBase(rel, base) => {
                write!(f, "Relative URL '{}' needs a resolved base", rel)
            }
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Config(e) => write!(f, "Configuration error: {}", e),
        }
    }
}

impl std::error::Error for TargetError {}

/// Authentication configuration for a target.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    /// Bearer token (for OAuth2, API keys, etc.).
    pub bearer: Option<String>,
    
    /// Basic auth credentials.
    pub basic: Option<(String, String)>,
    
    /// Custom headers to include with requests.
    pub headers: std::collections::HashMap<String, String>,
}

impl AuthConfig {
    pub fn new() -> Self {
        Default::default()
    }
    
    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }
    
    pub fn with_basic(mut self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.basic = Some((user.into(), pass.into()));
        self
    }
    
    pub fn with_header<K, V>(mut self, key: K, value: V) -> Self 
    where 
        K: Into<String>, 
        V: Into<String> 
    {
        let (k, v) = (key.into(), value.into());
        self.headers.insert(k, v);
        self
    }
}

/// A single target for DAST scanning.
#[derive(Debug, Clone)]
pub struct Target {
    /// The base URL to scan.
    pub url: Url,
    
    /// Authentication configuration.
    pub auth: AuthConfig,
    
    /// Scope definitions (endpoints to include/exclude).
    pub scopes: Vec<Scope>,
    
    /// Rate limiting hints (requests per second).
    pub rate_limit: Option<u64>,
    
    /// Custom request headers.
    pub headers: std::collections::HashMap<String, String>,
    
    /// Metadata for tracking and reporting.
    pub metadata: TargetMetadata,
}

impl Default for Target {
    fn default() -> Self {
        Self {
            url: Url::parse("https://example.com").unwrap(),
            auth: AuthConfig::default(),
            scopes: Vec::new(),
            rate_limit: None,
            headers: std::collections::HashMap::new(),
            metadata: TargetMetadata::default(),
        }
    }
}

impl Target {
    /// Create a new target with the given base URL.
    pub fn new(url: impl Into<Url>) -> Self {
        let url = url.into();
        
        // Validate the URL is well-formed
        if url.scheme() != "http" && url.scheme() != "https" {
            panic!("Target must use http or https scheme");
        }
        
        Target {
            url,
            auth: AuthConfig::default(),
            scopes: Vec::new(),
            rate_limit: None,
            headers: std::collections::HashMap::new(),
            metadata: TargetMetadata::default(),
        }
    }
    
    /// Create a target with authentication.
    pub fn with_auth(url: impl Into<Url>, auth: AuthConfig) -> Self {
        let url = url.into();
        Target {
            url,
            auth,
            scopes: Vec::new(),
            rate_limit: None,
            headers: std::collections::HashMap::new(),
            metadata: TargetMetadata::default(),
        }
    }
    
    /// Create a target with scopes.
    pub fn with_scopes(url: impl Into<Url>, scopes: Vec<Scope>) -> Self {
        let url = url.into();
        Target {
            url,
            auth: AuthConfig::default(),
            scopes,
            rate_limit: None,
            headers: std::collections::HashMap::new(),
            metadata: TargetMetadata::default(),
        }
    }
    
    /// Create a target with all options.
    pub fn full(
        url: impl Into<Url>,
        auth: AuthConfig,
        scopes: Vec<Scope>,
        rate_limit: Option<u64>,
        headers: std::collections::HashMap<String, String>,
    ) -> Self {
        let url = url.into();
        Target {
            url,
            auth,
            scopes,
            rate_limit,
            headers,
            metadata: TargetMetadata::default(),
        }
    }
    
    /// Check if this target matches a given path pattern.
    pub fn matches_path(&self, path: &str) -> bool {
        let target_path = self.url.path();
        
        // Exact match
        if target_path == path || target_path.ends_with(path) {
            return true;
        }
        
        // Prefix match (for API endpoints like /api/v1/...)
        if target_path.starts_with(&path[..]) && 
           !target_path.contains(&format!("{}.", &path)) {
            return true;
        }
        
        false
    }
    
    /// Check if this target is within a scope.
    pub fn in_scope(&self, scope: &Scope) -> bool {
        let path = self.url.path();
        
        match scope {
            Scope::Include(patterns) => {
                patterns.iter().any(|p| matches_path(path, p))
            }
            Scope::Exclude(patterns) => {
                !patterns.iter().any(|p| matches_path(path, p))
            }
        }
    }
    
    /// Create a new target with merged scopes.
    pub fn merge_scopes(&mut self, scopes: Vec<Scope>) {
        if !self.scopes.is_empty() && !scopes.is_empty() {
            // Combine include and exclude lists
            let mut includes = Vec::new();
            let mut excludes = Vec::new();
            
            for s in &self.scopes {
                match s {
                    Scope::Include(p) => includes.extend_from_slice(p),
                    Scope::Exclude(p) => excludes.extend_from_slice(p),
                }
            }
            
            for s in scopes {
                match s {
                    Scope::Include(p) => includes.extend_from_slice(p),
                    Scope::Exclude(p) => excludes.extend_from_slice(p),
                }
            }
            
            self.scopes = vec![Scope::Include(includes)];
        } else {
            self.scopes = scopes;
        }
    }
    
    /// Create a new target with merged headers.
    pub fn merge_headers(&mut self, other: &Self) -> Self {
        let mut combined = Self {
            url: self.url.clone(),
            auth: AuthConfig::default(),
            scopes: Vec::new(),
            rate_limit: None,
            headers: std::collections::HashMap::new(),
            metadata: TargetMetadata::default(),
        };
        
        // Merge authentication (later wins)
        if !self.auth.bearer.is_none() {
            combined.auth = self.auth.clone();
        } else if !other.auth.bearer.is_none() {
            combined.auth = other.auth.clone();
        }
        
        // Merge headers (later wins)
        for (k, v) in &self.headers {
            combined.headers.insert(k.clone(), v.clone());
        }
        for (k, v) in &other.headers {
            combined.headers.entry(k.clone()).or_insert(v.clone());
        }
        
        combined
    }
    
    /// Check if this target is a duplicate of another.
    pub fn is_duplicate_of(&self, other: &Self) -> bool {
        // Compare normalized URLs (same host + path, ignoring query/fragment)
        let self_normalized = format!("{}{}", self.url.host_str().unwrap_or(""), 
                                        self.url.path());
        let other_normalized = format!("{}{}", other.url.host_str().unwrap_or(""), 
                                       other.url.path());
        
        // Compare auth presence (not exact values for simplicity)
        let self_has_auth = !self.auth.bearer.is_none() || 
                          !self.auth.basic.is_none() || 
                          !self.auth.headers.is_empty();
        let other_has_auth = !other.auth.bearer.is_none() || 
                            !other.auth.basic.is_none() || 
                            !other.auth.headers.is_empty();
        
        self_normalized == other_normalized && 
        self_has_auth == other_has_auth
    }
}

/// Scope definitions for filtering target paths.
#[derive(Debug, Clone)]
pub enum Scope {
    /// Paths that should be included in the scan.
    Include(Vec<String>),
    
    /// Paths that should be excluded from the scan.
    Exclude(Vec<String>),
}

impl Default for Scope {
    fn default() -> Self {
        Scope::Include(vec!["/api/*".to_string(), "/graphql/*".to_string()])
    }
}

/// Metadata associated with a target (non-functional data).
#[derive(Debug, Clone, Default)]
pub struct TargetMetadata {
    /// Unique identifier for this target.
    pub id: Option<String>,
    
    /// Name or description of the target.
    pub name: Option<String>,
    
    /// Environment (dev, staging, prod).
    pub environment: Option<String>,
    
    /// Notes or comments.
    pub notes: Option<String>,
}

impl TargetMetadata {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: Some(id.into()),
            ..Default::default()
        }
    }
    
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// A collection of targets for batch operations.
#[derive(Debug, Clone)]
pub struct TargetCollection {
    /// All discovered and configured targets.
    pub targets: Vec<Target>,
    
    /// Source information (files, commands that created this).
    pub sources: Vec<SourceInfo>,
}

impl Default for TargetCollection {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            sources: Vec::new(),
        }
    }
}

impl TargetCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Default::default()
    }
    
    /// Add a target to the collection, returning an error if duplicate.
    pub fn add(&mut self, target: Target) -> Result<(), TargetError> {
        // Check for duplicates before adding
        let key = normalize_target_key(&target);
        
        if self.targets.iter().any(|t| normalize_target_key(t) == key) {
            return Err(TargetError::Duplicate(key));
        }
        
        self.targets.push(target);
        Ok(())
    }
    
    /// Add multiple targets, deduplicating as we go.
    pub fn extend(&mut self, others: impl IntoIterator<Item = Target>) -> Result<(), TargetError> {
        for target in others.into_iter() {
            self.add(target)?;
        }
        Ok(())
    }
    
    /// Remove all targets matching a given URL prefix.
    pub fn remove_by_prefix(&mut self, prefix: &str) {
        let normalized = normalize_url(prefix);
        
        self.targets.retain(|t| {
            !t.url.as_str().starts_with(&normalized)
        });
    }
    
    /// Get a deduplicated list of unique base URLs.
    pub fn unique_bases(&self) -> Vec<Url> {
        let mut seen = std::collections::HashSet::new();
        let mut bases: Vec<_> = self.targets.iter()
            .map(|t| t.url.clone())
            .filter(|u| !seen.contains(u))
            .collect();
        
        // Sort for consistent output
        bases.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        bases
    }
    
    /// Calculate total scope coverage.
    pub fn total_scope_count(&self) -> usize {
        self.targets.iter()
            .map(|t| t.scopes.len())
            .sum()
    }
}

/// Source information for tracking where targets came from.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// The source file or command that added these targets.
    pub path: PathBuf,
    
    /// Line number (if applicable).
    pub line: Option<usize>,
}

/// Helper functions for URL normalization and comparison.
fn normalize_url(url: &str) -> String {
    // Remove query string and fragment for base comparison
    let parts: Vec<&str> = url.splitn(2, '?').collect();
    if parts.len() == 1 {
        parts[0].to_string()
    } else {
        format!("{}?", parts[0])
    }
}

fn normalize_target_key(target: &Target) -> String {
    // Create a canonical key for duplicate detection
    let base = normalize_url(&target.url);
    
    // Include auth presence in the key (not exact values)
    let auth_part = if target.auth.bearer.is_some() || 
                     target.auth.basic.is_some() || 
                     !target.auth.headers.is_empty() {
        "with_auth"
    } else {
        "no_auth"
    };
    
    format!("{}|{}", base, auth_part)
}

/// Helper function to match a path against a pattern.
fn matches_path(path: &str, pattern: &str) -> bool {
    // Simple glob-like matching (not full regex for performance)
    let mut p = pattern;
    
    // Handle wildcards
    if p.contains('*') || p.contains('?') {
        use fnmatch::FnMatch;
        return path.fnmatch(p).unwrap_or(false);
    }
    
    // Exact match (after stripping trailing slash for comparison)
    let clean_path = path.trim_end_matches('/');
    let clean_pattern = pattern.trim_end_matches('/');
    
    clean_path == clean_pattern || 
    clean_path.ends_with(clean_pattern)
}

/// Create a target manager instance.
pub fn create_target_manager() -> TargetCollection {
    TargetCollection::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_target_creation() {
        let t = Target::new("https://api.example.com/v1");
        assert_eq!(t.url.as_str(), "https://api.example.com/v1");
    }
    
    #[test]
    fn test_scope_matching() {
        let mut target = Target::new("https://api.example.com/v1/users/123");
        
        // Add include scope for API paths
        target.merge_scopes(vec![Scope::Include(vec!["/v1/*".to_string()])]);
        
        assert!(target.in_scope(&Scope::Include(vec!["/v1/*".to_string()])));
    }
    
    #[test]
    fn test_collection_deduplication() {
        let mut collection = TargetCollection::new();
        
        // Add first target
        let t1 = Target::full(
            "https://api.example.com/v1",
            AuthConfig::default(),
            vec![],
            None,
            std::collections::HashMap::new(),
        );
        collection.add(t1).unwrap();
        
        // Add duplicate (same URL, same auth)
        let t2 = Target::full(
            "https://api.example.com/v1",