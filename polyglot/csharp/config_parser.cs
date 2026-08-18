using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace polyglot.csharp
{
    // =====================================================================
    // CONFIGURATION SCHEMA
    // =====================================================================

    /// <summary>
    /// Root configuration object for dastlite.
    /// </summary>
    public sealed class Config
    {
        [JsonPropertyName("targets")]
        public List<UrlTarget> Targets { get; set; } = new();

        [JsonPropertyName("authentication")]
        public AuthConfig Authentication { get; set; } = default!;

        [JsonPropertyName("ruleset")]
        public RulesetConfig Ruleset { get; set; } = default!;

        [JsonPropertyName("output")]
        public OutputConfig Output { get; set; } = default!;

        [JsonPropertyName("limits")]
        public LimitsConfig Limits { get; set; } = default!;

        /// <summary>
        /// Whether to enable verbose logging.
        /// </summary>
        [JsonPropertyName("verbose")]
        public bool Verbose { get; set; } = false;

        /// <summary>
        /// Environment variable substitution prefix (e.g., "env:").
        /// </summary>
        [JsonPropertyName("env_prefix")]
        public string EnvPrefix { get; set; } = "env:";
    }

    /// <summary>
    /// URL target definition.
    /// </summary>
    public sealed class UrlTarget
    {
        [JsonPropertyName("url")]
        public required string Url { get; set; }

        [JsonPropertyName("method")]
        public string Method { get; set; } = "GET";

        [JsonPropertyName("headers")]
        public Dictionary<string, string> Headers { get; set; } = new();

        [JsonPropertyName("params")]
        public Dictionary<string, string> Params { get; set; } = new();

        [JsonPropertyName("body")]
        public string Body { get; set; } = null!;

        /// <summary>
        /// Whether this is a mobile API target.
        /// </summary>
        [JsonPropertyName("mobile_api")]
        public bool MobileApi { get; set; } = false;
    }

    /// <summary>
    /// Authentication configuration.
    /// </summary>
    public sealed class AuthConfig
    {
        [JsonPropertyName("type")]
        public required string Type { get; set; }

        [JsonPropertyName("api_key")]
        public string ApiKey { get; set; } = null!;

        [JsonPropertyName("bearer_token")]
        public string BearerToken { get; set; } = null!;

        [JsonPropertyName("oauth_client_id")]
        public string OAuthClientId { get; set; } = null!;

        [JsonPropertyName("oauth_client_secret")]
        public string OAuthClientSecret { get; set; } = null!;

        /// <summary>
        /// Whether to use session cookies for auth.
        /// </summary>
        [JsonPropertyName("session_cookie")]
        public bool SessionCookie { get; set; } = false;
    }

    /// <summary>
    /// Ruleset configuration - defines what scans to run.
    /// </summary>
    public sealed class RulesetConfig
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [JsonPropertyName("rules")]
        public List<RuleDefinition> Rules { get; set; } = new();

        /// <summary>
        /// Whether to run in "discover" mode (auto-detect endpoints).
        /// </summary>
        [JsonPropertyName("discover_mode")]
        public bool DiscoverMode { get; set; } = false;

        /// <summary>
        /// Custom headers to inject into all requests.
        /// </summary>
        [JsonPropertyName("global_headers")]
        public Dictionary<string, string> GlobalHeaders { get; set; } = new();
    }

    /// <summary>
    /// Individual rule definition.
    /// </summary>
    public sealed class RuleDefinition
    {
        [JsonPropertyName("id")]
        public required string Id { get; set; }

        [JsonPropertyName("name")]
        public required string Name { get; set; }

        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [JsonPropertyName("type")]
        public required string Type { get; set; }

        /// <summary>
        /// Parameters passed to the rule engine.
        /// </summary>
        [JsonPropertyName("params")]
        public Dictionary<string, object> Params { get; set; } = new();

        /// <summary>
        /// Severity threshold (Info, Low, Medium, High, Critical).
        /// </summary>
        [JsonPropertyName("severity_threshold")]
        public string? SeverityThreshold { get; set; }

        /// <summary>
        /// Whether to skip this rule if a higher severity is found.
        /// </summary>
        [JsonPropertyName("skip_on_higher_severity")]
        public bool SkipOnHigherSeverity { get; set; } = false;
    }

    /// <summary>
    /// Output configuration - where and how to emit results.
    /// </summary>
    public sealed class OutputConfig
    {
        [JsonPropertyName("format")]
        public required string Format { get; set; } // "sarif", "json", "text"

        [JsonPropertyName("path")]
        public string Path { get; set; } = null!;

        /// <summary>
        /// Whether to include debug metadata in output.
        /// </summary>
        [JsonPropertyName("debug_metadata")]
        public bool DebugMetadata { get; set; } = false;

        /// <summary>
        /// Maximum number of findings to emit (0 = unlimited).
        /// </summary>
        [JsonPropertyName("max_findings")]
        public int MaxFindings { get; set; } = 0;
    }

    /// <summary>
    /// Rate limiting and concurrency configuration.
    /// </summary>
    public sealed class LimitsConfig
    {
        [JsonPropertyName("rate_limit")]
        public float RateLimit { get; set; } // requests per second

        [JsonPropertyName("concurrency")]
        public int Concurrency { get; set; } = 4;

        /// <summary>
        /// Retry count on transient failures.
        /// </summary>
        [JsonPropertyName("retry_count")]
        public int RetryCount { get; set; } = 3;

        /// <summary>
        /// Backoff multiplier for retries (exponential backoff).
        /// </summary>
        [JsonPropertyName("backoff_multiplier")]
        public float BackoffMultiplier { get; set; } = 2.0f;
    }

    // =====================================================================
    // CONFIG PARSER IMPLEMENTATION
    // =====================================================================

    /// <summary>
    /// Static parser for loading and validating dastlite configuration.
    /// </summary>
    public static class ConfigParser
    {
        private const string DefaultConfigPath = "dastlite.config.json";
        private const string EnvVarPrefix = "DASTLITE_";

        /// <summary>
        /// Loads configuration from a file path or default location.
        /// </summary>
        public static Config Load(string? path = null)
        {
            var fullPath = ResolveConfigPath(path);
            
            if (!File.Exists(fullPath))
            {
                Console.WriteLine($"[CONFIG] No config found at: {fullPath}");
                return CreateDefault();
            }

            try
            {
                return LoadFromStream(File.OpenRead(fullPath));
            }
            catch (JsonException ex)
            {
                throw new ConfigLoadException(
                    $"Invalid JSON in config file: {ex.Message}", 
                    ex);
            }
        }

        /// <summary>
        /// Loads configuration from an existing stream.
        /// </summary>
        public static Config LoadFromStream(Stream stream)
        {
            using var reader = new StreamReader(stream);
            return LoadFromText(reader.ReadToEnd());
        }

        /// <summary>
        /// Parses configuration text directly (useful for CLI args).
        /// </summary>
        public static Config LoadFromText(string jsonText)
        {
            try
            {
                var config = JsonSerializer.Deserialize<Config>(jsonText);
                
                if (config == null)
                    throw new ConfigLoadException("Deserialized to null - check JSON structure");

                // Apply environment variable substitution
                SubstituteEnvVars(config);

                // Validate required fields
                ValidateConfig(config);

                return config;
            }
            catch (JsonException ex)
            {
                throw new ConfigLoadException($"JSON parse error: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Creates a default configuration with sensible defaults.
        /// </summary>
        public static Config CreateDefault()
        {
            return new Config
            {
                Targets = new List<UrlTarget>
                {
                    new UrlTarget 
                    { 
                        Url = "https://example.com/api/v1",
                        Headers = { { "Accept", "application/json" } },
                        Params = { { "format", "json" } }
                    }
                },
                Authentication = new AuthConfig
                {
                    Type = "bearer_token",
                    BearerToken = "${DASTLITE_BEARER_TOKEN}"
                },
                Ruleset = new RulesetConfig
                {
                    Enabled = true,
                    DiscoverMode = false,
                    GlobalHeaders = { { "X-Client-ID", "dastlite" } }
                },
                Output = new OutputConfig
                {
                    Format = "sarif",
                    Path = "./output/dastlite.sarif",
                    MaxFindings = 1000,
                    DebugMetadata = false
                },
                Limits = new LimitsConfig
                {
                    RateLimit = 5.0f,
                    Concurrency = 4,
                    RetryCount = 3,
                    BackoffMultiplier = 2.0f
                }
            };
        }

        /// <summary>
        /// Resolves the config file path.
        /// </summary>
        private static string ResolveConfigPath(string? explicitPath)
        {
            if (!string.IsNullOrEmpty(explicitPath))
                return Path.GetFullPath(explicitPath);

            // Look in current directory, then home directory
            var candidates = new[]
            {
                DefaultConfigPath,
                Path.Combine(Environment.CurrentDirectory, DefaultConfigPath),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.AppData), 
                           ".dastlite", DefaultConfigPath)
            };

            return candidates.FirstOrDefault(File.Exists) ?? 
                   Path.Combine(AppContext.BaseDirectory, DefaultConfigPath);
        }

        /// <summary>
        /// Substitutes environment variables in string values.
        /// </summary>
        private static void SubstituteEnvVars(Config config)
        {
            var prefix = config.EnvPrefix;
            
            // Helper to substitute a single string value
            Func<string, string?> subString = (s) => 
                s?.Replace(prefix, "", StringComparison.OrdinalIgnoreCase);

            // Targets
            foreach (var target in config.Targets)
            {
                target.Url = subString(target.Url);
                if (!string.IsNullOrEmpty(target.Body))
                    target.Body = subString(target.Body);
                
                foreach (var header in target.Headers)
                    header.Value = subString(header.Value);

                foreach (var param in target.Params)
                    param.Value = subString(param.Value);
            }

            // Authentication
            config.Authentication.ApiKey = subString(config.Authentication.ApiKey);
            config.Authentication.BearerToken = subString(config.Authentication.BearerToken);
            config.Authentication.OAuthClientId = subString(config.Authentication.OAuthClientId);
            config.Authentication.OAuthClientSecret = subString(config.Authentication.OAuthClientSecret);

            // Ruleset params (if any)
            foreach (var rule in config.Ruleset.Rules)
            {
                if (rule.Params != null)
                {
                    foreach (var param in rule.Params)
                        param.Value = subString(param.Value?.ToString());
                }
            }

            // Output path
            config.Output.Path = subString(config.Output.Path);
        }

        /// <summary>
        /// Validates the configuration and throws if invalid.
        /// </summary>
        private static void ValidateConfig(Config config)
        {
            var errors = new List<string>();

            // Check targets
            if (config.Targets.Count == 0)
                errors.Add("At least one target URL must be defined");

            foreach (var target in config.Targets)
            {
                if (string.IsNullOrWhiteSpace(target.Url))
                    errors.Add($"Target missing URL: {target.Method}");
                
                try 
                { 
                    new Uri(target.Url); // Will throw if invalid URI
                }
                catch (UriFormatException ex)
                {
                    errors.Add($"Invalid target URL format: {ex.Message}");
                }

                if (!string.IsNullOrEmpty(target.Body))
                {
                    var bodyLen = target.Body.Length;
                    if (bodyLen > 1024 * 1024) // 1MB limit
                        errors.Add($"Target body exceeds 1MB limit: {bodyLen} bytes");
                }
            }

            // Check authentication
            switch (config.Authentication.Type.ToLowerInvariant())
            {
                case "bearer_token":
                    if (string.IsNullOrEmpty(config.Authentication.BearerToken))
                        errors.Add("Bearer token is required for bearer_token auth type");
                    break;
                case "api_key":
                    if (string.IsNullOrEmpty(config.Authentication.ApiKey))
                        errors.Add("API key is required for api_key auth type");
                    break;
                case "oauth2":
                    if (string.IsNullOrEmpty(config.Authentication.OAuthClientId) ||
                        string.IsNullOrEmpty(config.Authentication.OAuthClientSecret))
                        errors.Add("OAuth client ID and secret are required for oauth2 auth type");
                    break;
                default:
                    errors.Add($"Unknown authentication type: {config.Authentication.Type}");
                    break;
            }

            // Check ruleset
            if (!config.Ruleset.Enabled && config.Ruleset.Rules.Count > 0)
                Console.WriteLine("[CONFIG] Ruleset disabled but contains definitions - ignoring");

            foreach (var rule in config.Ruleset.Rules)
            {
                if (string.IsNullOrWhiteSpace(rule.Id))
                    errors.Add($"Rule missing ID: {rule.Name}");
                
                if (string.IsNullOrWhiteSpace(rule.Type))
                    errors.Add($"Rule missing type: {rule.Id}");
            }

            // Check output
            if (string.IsNullOrWhiteSpace(config.Output.Format))
                config.Output.Format = "sarif"; // sensible default

            if (config.Output.MaxFindings < 0)
                config.Output.MaxFindings = 0;

            // Report errors
            if (errors.Count > 0)
            {
                Console.WriteLine($"[CONFIG] Validation found {errors.Count} issue(s):");
                foreach (var error in errors)
                    Console.WriteLine($"    - {error}");
                
                throw new ConfigLoadException("Configuration validation failed", 
                    new AggregateException(errors));
            }

            // Warn about potential issues
            if (config.Limits.RateLimit > 100.0f)
                Console.WriteLine("[CONFIG] High rate limit detected: {0} req/s may cause throttling", 
                               config.Limits.RateLimit);

            if (config.Limits.Concurrency > 32)
                Console.WriteLine("[CONFIG] High concurrency ({0}) may increase memory usage", 
                               config.Limits.Concurrency);
        }

        /// <summary>
        /// Creates a deep copy of the configuration.
        /// </summary>
        public static Config Clone(Config source)
        {
            return JsonSerializer.Deserialize<Config>(JsonSerializer.Serialize(source))!;
        }

        /// <summary>
        /// Merges two configurations, with right-hand values taking precedence.
        /// </summary>
        public static Config Merge(Config baseConfig, Config overlay)
        {
            var merged = Clone(baseConfig);

            if (overlay != null)
            {
                // Deep merge - for production use, consider a proper deep-merge utility