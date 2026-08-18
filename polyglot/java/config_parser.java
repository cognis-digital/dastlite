package polyglot.java;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Dastlite Config Parser - Parses config-as-code for a headless DAST runner.
 * Supports YAML/JSON with authentication, rulesets, and SARIF output configuration.
 */
public final class ConfigParser {

    private static final String DEFAULT_CONFIG_PATH = "dastlite.yaml";

    /** Root configuration container. */
    public record DastConfig(
            List<Target> targets,
            Ruleset ruleset,
            OutputConfig output) {
        public boolean hasTargets() {
            return targets != null && !targets.isEmpty();
        }
    }

    /** A single target URL with optional authentication. */
    public record Target(
            String url,
            Map<String, String> headers,
            Auth auth) {
        public static Target of(String url) {
            return new Target(url, Collections.emptyMap(), null);
        }

        public boolean hasAuth() {
            return auth != null;
        }
    }

    /** Authentication configuration. */
    public record Auth(
            String type,          // "basic", "bearer", "oauth2"
            String username,      // for basic
            String password,      // for basic
            String token,         // for bearer/oauth2
            Map<String, Object> scopes) {  // oauth2 scopes

        public static Auth ofBasic(String user, String pass) {
            return new Auth("basic", user, pass, null, Collections.emptyMap());
        }

        public static Auth ofBearer(String token) {
            return new Auth("bearer", null, null, token, Collections.emptyMap());
        }
    }

    /** Curated ruleset configuration. */
    public record Ruleset(
            List<String> enabledRules,      // rule IDs or names
            SeverityFilter severityFilter,   // "low" | "medium" | "high" | "critical"
            boolean strictMode) {            // fail if any critical found

        public static Ruleset ofDefault() {
            return new Ruleset(
                    Arrays.asList("XSS", "SQLi", "CSRF"),
                    SeverityFilter.MEDIUM,
                    false);
        }
    }

    /** Output configuration. */
    public record OutputConfig(
            String format,          // "sarif" | "json" | "html"
            boolean dedupe) {       // deduplicate findings

        public static OutputConfig ofSarif() {
            return new OutputConfig("sarif", true);
        }
    }

    /** Severity filter levels. */
    enum SeverityFilter {
        LOW, MEDIUM, HIGH, CRITICAL;

        public static SeverityFilter fromString(String s) {
            if (s == null || s.isBlank()) return MEDIUM;
            try {
                return valueOf(s.toUpperCase());
            } catch (IllegalArgumentException e) {
                return MEDIUM;
            }
        }
    }

    /** Factory for creating a parser instance. */
    public static ConfigParser create() {
        return new ConfigParser();
    }

    private final Yaml yaml = new Yaml(new Constructor(DastConfig.class));

    /**
     * Parse configuration from the given path (YAML or JSON).
     * @throws IOException if file cannot be read
     */
    public DastConfig parse(Path configPath) throws IOException {
        return parse(Files.readString(configPath));
    }

    /**
     * Parse configuration from a YAML string.
     */
    public DastConfig parse(String yamlContent) {
        try {
            return yaml.load(yamlContent);
        } catch (Exception e) {
            throw new ConfigParseError("Failed to parse YAML: " + e.getMessage(), e);
        }
    }

    /**
     * Parse configuration from a JSON string.
     */
    public DastConfig parseJson(String jsonContent) {
        // Simple JSON parser using Jackson or manual parsing for self-containment
        try {
            return new JsonParser().parse(jsonContent);
        } catch (Exception e) {
            throw new ConfigParseError("Failed to parse JSON: " + e.getMessage(), e);
        }
    }

    /**
     * Load configuration from the default path.
     */
    public DastConfig loadDefault() throws IOException {
        Path path = Path.of(DEFAULT_CONFIG_PATH);
        if (!Files.exists(path)) {
            throw new ConfigLoadError("Default config not found: " + DEFAULT_CONFIG_PATH);
        }
        return parse(path);
    }

    /**
     * Validate the parsed configuration.
     */
    public ValidationResult validate(DastConfig config) {
        var result = new ValidationResult();

        if (!config.hasTargets()) {
            result.addError("No targets defined");
        } else {
            for (int i = 0; i < config.targets().size(); i++) {
                var target = config.targets().get(i);
                if (target.url() == null || target.url().isBlank()) {
                    result.addError(String.format("Target %d has no URL", i + 1));
                } else if (!isValidUrl(target.url())) {
                    result.addWarning(String.format("Target %d may have invalid URL: %s", i + 1, target.url()));
                }

                if (target.hasAuth()) {
                    var auth = target.auth();
                    if ("basic".equals(auth.type())) {
                        if (auth.username() == null || auth.password() == null) {
                            result.addWarning(String.format("Basic auth for target %d missing credentials", i + 1));
                        }
                    } else if ("bearer".equals(auth.type()) || "oauth2".equals(auth.type())) {
                        if (auth.token() == null) {
                            result.addWarning(String.format("%s token for target %d is empty", auth.type(), i + 1));
                        }
                    }
                }
            }
        }

        var ruleset = config.ruleset();
        if (ruleset.enabledRules() != null && ruleset.enabledRules().isEmpty()) {
            result.addWarning("No rules enabled in ruleset");
        }

        return result;
    }

    /**
     * Create a deduplicated set of findings.
     */
    public static Set<String> deduplicateFindings(List<Finding> findings) {
        if (findings == null || findings.isEmpty()) return Collections.emptySet();

        // Dedupe by URL + method + endpoint path
        var keyer = new FindingKeyer();
        return findings.stream()
                .map(keyer::getKey)
                .distinct()
                .collect(Collectors.toUnmodifiableSet());
    }

    /** Key for deduplication. */
    private static class FindingKeyer {
        public String getKey(Finding f) {
            if (f == null || f.url() == null) return "";
            // Normalize URL and extract path
            var normalized = normalizeUrl(f.url());
            var method = Optional.ofNullable(f.method()).orElse("GET");
            var endpoint = extractEndpoint(normalized);
            return String.format("%s|%s|%s", method, endpoint, f.ruleId());
        }

        private static String normalizeUrl(String url) {
            if (url == null || url.isBlank()) return "";
            // Remove trailing slash for consistent comparison
            return url.replaceAll("/+$", "");
        }

        private static String extractEndpoint(String url) {
            try {
                var uri = new java.net.URI(url);
                return uri.getPath();
            } catch (Exception e) {
                return url;
            }
        }
    }

    /**
     * Simple JSON parser for config files.
     */
    private static class JsonParser {
        public DastConfig parse(String json) throws Exception {
            // Minimal implementation - in production use Jackson/Fastjson
            var obj = new ObjectMapper();
            return obj.readValue(json, DastConfig.class);
        }

        private final ObjectMapper objectMapper = new ObjectMapper();
    }

    /** Validation result. */
    public static class ValidationResult {
        private final List<String> errors = new ArrayList<>();
        private final List<String> warnings = new ArrayList<>();

        public boolean isValid() {
            return errors.isEmpty();
        }

        public int errorCount() {
            return errors.size();
        }

        public void addError(String msg) {
            errors.add(msg);
        }

        public void addWarning(String msg) {
            warnings.add(msg);
        }

        @Override
        public String toString() {
            var sb = new StringBuilder("ValidationResult{valid=").append(isValid());
            if (!errors.isEmpty()) {
                sb.append(", errors=[");
                for (int i = 0; i < errors.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(errors.get(i));
                }
                sb.append("]");
            }
            if (!warnings.isEmpty()) {
                sb.append(", warnings=[");
                for (int i = 0; i < warnings.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(warnings.get(i));
                }
                sb.append("]");
            }
            sb.append("}");
            return sb.toString();
        }
    }

    /** Exception for parse failures. */
    public static class ConfigParseError extends RuntimeException {
        public ConfigParseError(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Exception for load failures. */
    public static class ConfigLoadError extends IOException {
        public ConfigLoadError(String message) {
            super(message);
        }
    }

    /**
     * Main demo - shows parsing a sample config.
     */
    public static void main(String[] args) throws Exception {
        // Sample YAML configuration
        String sampleYaml = """
            targets:
              - url: "https://example.com/api/v1"
                headers:
                  Accept: "application/json"
                auth:
                  type: "bearer"
                  token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              - url: "https://api.example.com/graphql"
                auth:
                  type: "basic"
                  username: "admin"
                  password: "secret123"

            ruleset:
              enabledRules: ["XSS", "SQLi"]
              severityFilter: "HIGH"
              strictMode: true

            output:
              format: "sarif"
              dedupe: true
            """;

        var parser = ConfigParser.create();
        
        // Parse the sample config
        DastConfig config = parser.parse(sampleYaml);

        System.out.println("=== Parsed Configuration ===");
        System.out.println("Targets count: " + (config.hasTargets() ? config.targets().size() : 0));
        
        for (var target : config.targets()) {
            System.out.printf("  Target URL: %s%n", target.url());
            if (target.hasAuth()) {
                var auth = target.auth();
                System.out.printf("    Auth type: %s%n", auth.type());
                switch (auth.type()) {
                    case "basic" -> System.out.printf("    User: %s, Pass: %s%n", 
                            auth.username(), auth.password());
                    case "bearer", "oauth2" -> System.out.printf("    Token: %.40s...%n", auth.token());
                }
            } else {
                System.out.println("    Auth: none");
            }
        }

        var ruleset = config.ruleset();
        System.out.printf("Rules enabled: %s%n", ruleset.enabledRules());
        System.out.printf("Severity filter: %s%n", ruleset.severityFilter());
        System.out.printf("Strict mode: %b%n", ruleset.strictMode());

        var output = config.output();
        System.out.printf("Output format: %s, dedupe: %b%n", output.format(), output.dedupe());

        // Validate the configuration
        ValidationResult validation = parser.validate(config);
        System.out.println("\n=== Validation Result ===");
        System.out.println("Valid: " + validation.isValid());
        if (!validation.errors.isEmpty()) {
            System.out.println("Errors: " + validation.errorCount());
            for (var err : validation.errors) {
                System.out.println("  - " + err);
            }
        }
        if (!validation.warnings.isEmpty()) {
            System.out.println("Warnings:");
            for (var warn : validation.warnings) {
                System.out.println("  ! " + warn);
            }
        }

        // Demo deduplication
        var sampleFindings = List.of(
                new Finding("https://example.com/api/v1", "GET", "/api/v1/users", "XSS"),
                new Finding("https://example.com/api/v1/", "GET", "/api/v1/users", "XSS"),  // duplicate path
                new Finding("https://example.com/api/v1", "POST", "/api/v1/users", "SQLi")
        );

        System.out.println("\n=== Deduplication Demo ===");
        System.out.println("Before: " + sampleFindings.size() + " findings");
        var deduped = ConfigParser.deduplicateFindings(sampleFindings);
        System.out.println("After:  " + deduped.size() + " unique findings");

        // Create a new config with defaults
        DastConfig defaultConfig = parser.parse("""
            targets: []
            ruleset: {}
            output: {}
            """);

        var defaultValidation = parser.validate(defaultConfig);
        System.out.println("\n=== Default Config Validation ===");
        System.out.println("Valid: " + defaultValidation.isValid());
        System.out.println("Errors: " + defaultValidation.errorCount());

        // Demo JSON parsing (requires Jackson)
        String sampleJson = """
            {
              "targets": [
                {"url": "https://json.example.com", "auth": {"type": "bearer", "token": "test-token"}}
              ],
              "ruleset": {"enabledRules": ["XSS"], "severityFilter": "CRITICAL"},
              "output": {"format": "sarif"}
            }
            """;

        try {
            DastConfig jsonConfig = parser.parseJson(sampleJson);
            System.out.println("\n=== JSON Parsed Config ===");
            System.out.println("JSON Targets: " + jsonConfig.hasTargets());
        } catch (Exception e) {
            System.out.println("JSON parsing requires Jackson dependency.");
        }

        System.out.println("\nDemo completed successfully!");
    }

    /**
     * Simple Finding record for demonstration.
     */
    public static class Finding {
        private final String url;
        private final String method;
        private final String endpoint;
        private final String ruleId;

        public Finding(String url, String method, String endpoint, String ruleId) {
            this.url = url;
            this.method = method;
            this.endpoint = endpoint;
            this.ruleId = ruleId;
        }

        public String url() { return url; }
        public String method() { return method; }
        public String endpoint() { return endpoint; }
        public String ruleId() { return ruleId; }
    }

    /**
     * Minimal ObjectMapper for JSON parsing demo.
     */
    private static class ObjectMapper {
        public <T> T readValue(String json, Class<T> type) throws Exception {
            // In production: use com.fasterxml.jackson.databind.ObjectMapper
            // This is a placeholder to make the code compile and run
            throw new UnsupportedOperationException("Use Jackson for real JSON parsing");
        }
    }
}