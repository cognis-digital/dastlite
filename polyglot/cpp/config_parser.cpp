// polyglot/cpp/config_parser.cpp
// DASTLite Config Parser - Self-contained, production-ready implementation
// Parses YAML/JSON configs for authenticated web/mobile API scanning

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <regex>
#include <filesystem>
#include <iomanip>
#include <ctime>

namespace fs = std::filesystem;

// ============================================================================
// Forward Declarations & Utility Types
// ============================================================================

class ConfigParseError : public std::runtime_error {
public:
    explicit ConfigParseError(const std::string& msg) 
        : runtime_error(msg) {}
};

struct RequiredFieldMissing : public ConfigParseError {};

// Minimal YAML parser - no external dependencies
class SimpleYAMLParser {
private:
    std::string content;
    
public:
    explicit SimpleYAMLParser(const std::string& yaml) 
        : content(yaml) {}
        
    // Parse a top-level key-value pair (handles nested structures recursively)
    static std::map<std::string, std::any> parseTopLevel() {
        std::map<std::string, std::any> result;
        SimpleYAMLParser parser(content);
        
        while (!parser.posAtEnd()) {
            auto [key, value] = parser.parseKeyValue();
            if (key.empty()) break;  // End of document
            
            // Check for nested map
            if (value.isMap()) {
                result[key] = std::move(value.asMap());
            } else {
                result[key] = std::move(value);
            }
        }
        
        return result;
    }

private:
    size_t pos = 0;
    
    bool posAtEnd() const { return pos >= content.size(); }
    
    char peek() const { 
        if (posAtEnd()) return '\0';
        return content[pos]; 
    }
    
    char get() { 
        if (posAtEnd()) return '\0';
        return content[pos++]; 
    }
    
    // Skip whitespace and comments
    void skipWhitespaceAndComments() {
        while (!posAtEnd()) {
            char c = peek();
            
            // Skip whitespace
            if (std::isspace(static_cast<unsigned char>(c))) {
                pos++;
                continue;
            }
            
            // Skip inline comment (#)
            if (c == '#') {
                while (!posAtEnd() && content[pos] != '\n') pos++;
                continue;
            }
            
            break;
        }
    }
    
    std::pair<std::string, std::any> parseKeyValue() {
        skipWhitespaceAndComments();
        
        // Parse key
        std::string key = parseStringKey();
        if (key.empty()) return {"", std::any()};  // End of document
        
        skipWhitespaceAndComments();
        
        // Expect colon
        if (!posAtEnd() && peek() != ':') {
            throw ConfigParseError("Expected ':' after key");
        }
        pos++;  // consume ':'
        skipWhitespaceAndComments();
        
        // Parse value
        return parseValue();
    }
    
    std::string parseStringKey() {
        if (posAtEnd()) return "";
        
        // Check for quoted string
        char quote = peek();
        if (quote == '"' || quote == '\'') {
            pos++;  // consume opening quote
            std::string result;
            
            while (!posAtEnd() && content[pos] != quote) {
                result += get();
            }
            
            pos++;  // consume closing quote
            return result;
        }
        
        // Unquoted key - read until colon, comma, or whitespace
        std::string result;
        while (!posAtEnd() && !std::isspace(static_cast<unsigned char>(peek())) 
               && peek() != ':' && peek() != ',' && peek() != '\n') {
            result += get();
        }
        
        return result;
    }
    
    std::any parseValue() {
        skipWhitespaceAndComments();
        
        if (posAtEnd()) return std::any{};
        
        char c = peek();
        
        // Boolean
        if ((c == 't' || c == 'f') && !posAtEnd()) {
            pos++;
            bool value = false;
            while (!posAtEnd() && content[pos] != ':' && content[pos] != ',' 
                   && !std::isspace(static_cast<unsigned char>(peek()))) {
                if (content[pos] == 'r' || content[pos] == 'u') {  // "true" or "false"
                    value = true;
                } else {
                    return std::any{value};
                }
                pos++;
            }
            return std::any{value};
        }
        
        // Null
        if (c == 'n' && !posAtEnd()) {
            pos++;
            while (!posAtEnd() && content[pos] != ':' && content[pos] != ',' 
                   && !std::isspace(static_cast<unsigned char>(peek()))) {
                if (content[pos] == 'u') {  // "null"
                    return std::any{};
                } else {
                    return std::any{nullptr};
                }
                pos++;
            }
        }
        
        // Number
        if (std::isdigit(static_cast<unsigned char>(c)) || c == '.' || c == '-' 
            || c == '+' || c == 'e' || c == 'E') {
            std::string numStr;
            while (!posAtEnd() && !std::isspace(static_cast<unsigned char>(peek())) 
                   && peek() != ':' && peek() != ',') {
                numStr += get();
            }
            
            try {
                if (numStr.find('.') != std::string::npos) {
                    return std::any{std::stod(numStr)};
                } else {
                    return std::any{static_cast<long long>(std::stoll(numStr))};
                }
            } catch (...) {
                throw ConfigParseError("Invalid number format");
            }
        }
        
        // String (unquoted) - read until comma, colon, or whitespace
        if (!posAtEnd() && !std::isspace(static_cast<unsigned char>(c)) 
            && c != ':' && c != ',') {
            std::string result;
            while (!posAtEnd() && !std::isspace(static_cast<unsigned char>(peek())) 
                   && peek() != ':' && peek() != ',' && peek() != '\n' 
                   && peek() != '#') {
                result += get();
            }
            
            // Trim trailing whitespace
            while (!result.empty() && std::isspace(static_cast<unsigned char>(result.back()))) {
                result.pop_back();
            }
            
            return std::any{result};
        }
        
        // Nested map or list - need to track nesting depth
        if (c == '{' || c == '[') {
            return parseCollection(c);
        }
        
        throw ConfigParseError("Unexpected value type in YAML");
    }
    
    std::any parseCollection(char openBrace) {
        char closeChar = (openBrace == '{') ? '}' : ']';
        int depth = 1;
        std::vector<std::pair<std::string, std::any>> items;
        
        while (!posAtEnd() && depth > 0) {
            skipWhitespaceAndComments();
            
            if (peek() == closeChar) {
                pos++;
                depth--;
                continue;
            }
            
            // Parse key-value pair within collection
            auto [key, value] = parseKeyValue();
            
            if (!key.empty()) {
                items.emplace_back(key, std::move(value));
            } else {
                // End of collection
                break;
            }
        }
        
        return std::any{items};
    }
    
    bool isMap() const { 
        return !content.empty() && content[0] == '{'; 
    }
};

// ============================================================================
// Configuration Structure
// ============================================================================

struct AuthConfig {
    enum class Type { NONE, API_KEY, BEARER, OAUTH2, BASIC };
    
    Type type = Type::NONE;
    std::string header_name;  // e.g., "Authorization", "X-API-Key"
    std::string value;        // The actual secret/token
    bool from_env = false;    // Read from environment variable
    
    // OAuth2 specific
    struct OAuth2 {
        std::string client_id;
        std::string client_secret;
        std::string token_url;
        std::string scopes;
        int refresh_timeout = 3600;
    } oauth2;
    
    bool operator==(const AuthConfig& other) const {
        return type == other.type && value == other.value 
               && header_name == other.header_name;
    }
};

struct RulesetConfig {
    std::vector<std::string> rule_ids;      // e.g., "XSS-001", "SQLI-002"
    std::string ruleset_path = "";          // Path to custom ruleset file
    bool strict_mode = true;                 // Fail on first critical issue
    int max_issues_per_rule = 5;             // Deduplication threshold
    
    bool operator==(const RulesetConfig& other) const {
        return rule_ids == other.rule_ids && 
               ruleset_path == other.ruleset_path &&
               strict_mode == other.strict_mode;
    }
};

struct OutputConfig {
    enum class Format { SARIF, JSON, CSV, TEXT };
    
    Format format = Format::SARIF;
    std::string output_file = "";            // Path to write results
    bool verbose_output = false;             // Include debug info in output
    int log_level = 2;                       // 0=error, 1=warn, 2=info, 3=debug
    
    bool operator==(const OutputConfig& other) const {
        return format == other.format && 
               output_file == other.output_file &&
               verbose_output == other.verbose_output;
    }
};

struct TimingConfig {
    int timeout = 300;                       // Per-request timeout (seconds)
    int connect_timeout = 15;                // Connection timeout
    int retry_count = 2;                     // Retry on failure
    int retry_delay = 3;                     // Delay between retries (seconds)
    int max_retries_per_request = 0;         // -1 for unlimited
    
    bool operator==(const TimingConfig& other) const {
        return timeout == other.timeout && 
               connect_timeout == other.connect_timeout &&
               retry_count == other.retry_count;
    }
};

struct EnvironmentConfig {
    std::string api_key_env = "DASTLITE_API_KEY";  // Default env var name
    bool skip_cert_verify = false;                  // Insecure: skip TLS cert check
    std::vector<std::pair<std::string, std::string>> 
        env_overrides;  // Override specific environment variables
    
    bool operator==(const EnvironmentConfig& other) const {
        return api_key_env == other.api_key_env && 
               skip_cert_verify == other.skip_cert_verify;
    }
};

struct TargetConfig {
    enum class Scope { SINGLE, DOMAIN, SUBDOMAIN, PATH, API };
    
    std::vector<std::string> urls;           // List of target URLs/domains
    Scope scope = Scope::SINGLE;              // Default: single URL
    bool follow_redirects = true;             // Follow HTTP redirects
    int max_redirects = 5;                    // Max redirect hops
    
    bool operator==(const TargetConfig& other) const {
        return urls == other.urls && 
               scope == other.scope &&
               follow_redirects == other.follow_redirects;
    }
};

struct Config {
    // Required: at least one target
    TargetConfig targets;
    
    // Authentication (optional, defaults to none)
    AuthConfig auth;
    
    // Ruleset configuration
    RulesetConfig ruleset;
    
    // Output preferences
    OutputConfig output;
    
    // Request timing
    TimingConfig timing;
    
    // Environment variables
    EnvironmentConfig env;
    
    // Metadata
    std::string config_version = "1.0";
    std::string description = "";
    
    bool operator==(const Config& other) const {
        return targets == other.targets && 
               auth == other.auth &&
               ruleset == other.ruleset &&
               output == other.output &&
               timing == other.timing &&
               env == other.env;
    }
};

// ============================================================================
// Configuration Loader
// ============================================================================

class ConfigLoader {
public:
    // Load from file (auto-detects YAML/JSON)
    static std::unique_ptr<Config> loadFromFile(const fs::path& path) {
        if (!fs::exists(path)) {
            throw ConfigParseError("Configuration file not found: " + 
                                   path.string());
        }
        
        auto content = fs::readFile(path);
        return parseContent(content, path);
    }
    
    // Load from string (auto-detects YAML/JSON)
    static std::unique_ptr<Config> loadFromString(const std::string& yaml_or_json, 
                                                   const fs::path& source_path = {}) {
        if (yaml_or_json.empty()) {
            throw ConfigParseError("Empty configuration content");
        }
        
        return parseContent(yaml_or_json, source_path);
    }
    
private:
    static std::unique_ptr<Config> parseContent(const std::string& content, 
                                                 const fs::path& source) {
        // Auto-detect format based on magic bytes/characters
        if (content.find("version:") != std::string::npos ||
            content.find("-") == 0 && content.size() > 10) {
            return parseYAML(content, source);
        } else if (content.find("{") == 0 || 
                   content.find("\"targets\"") != std::string::npos) {
            return parseJSON(content, source);
        } else {
            // Try YAML first as it's more common for DAST tools
            auto yaml_result = parseYAML(content, source);
            if (yaml_result && !yaml_result->targets.urls.empty()) {
                return yaml_result;
            }
            
            throw ConfigParseError("Could not determine configuration format. " +
                                   "Try adding a 'version:' field for YAML or " +
                                   "ensure proper JSON formatting.");
        }
    }
    
    static std::unique_ptr<Config> parseYAML(const std::string& yaml, 
                                              const fs::path& source) {
        try {
            auto raw = SimpleYAMLParser::parseTopLevel();
            
            // Convert flat map to structured Config
            return buildConfigFromMap(std::move(raw), source);