// polyglot/cpp/target_manager.cpp
// DASTLite Target Manager - Complete Implementation
// 
// Architecture: Headless, config-as-code DAST runner component
// Capability: Target manager for authenticated web/mobile-API surfaces
// Output: Deduplicated SARIF emission pipeline

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>
#include <algorithm>
#include <functional>
#include <optional>
#include <filesystem>
#include <regex>
#include <iomanip>

namespace fs = std::filesystem;

// ============================================================================
// Configuration Types - Config-as-code foundation
// ============================================================================

struct TargetConfig {
    std::string name;
    std::string url;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> cookies;
    std::string auth_type = "basic"; // basic, bearer, oauth2, session
    std::string auth_token;
    int max_depth = 3;
    double rate_limit = 1.0; // requests per second
    bool follow_redirects = true;
    int redirect_max = 5;
};

struct DASTConfig {
    TargetConfig targets[4];
    int num_targets = 0;
    std::string output_sarif_path = "output.sarif";
    double global_rate_limit = 1.0;
    bool parallel_crawl = true;
    int max_threads = 2;
};

// ============================================================================
// HTTP Client - Minimal, robust implementation
// ============================================================================

class HttpClient {
public:
    struct Response {
        int status_code;
        std::string body;
        std::map<std::string, std::string> headers;
        bool success() const { return status_code >= 200 && status_code < 300; }
    };

private:
    std::string user_agent = "DASTLite/1.0";
    
public:
    Response get(const std::string& url, 
                 const std::map<std::string, std::string>& headers) {
        Response resp{200, "", {}};
        
        // Build request line and headers
        std::ostringstream req;
        req << "GET " << url << " HTTP/1.1\r\n";
        req << "Host: ";
        
        auto host_pos = url.find("://");
        if (host_pos != std::string::npos) {
            auto colon_pos = url.find(':', host_pos);
            resp.headers["Host"] = url.substr(host_pos + 3, 
                colon_pos - host_pos - 3);
        } else {
            resp.headers["Host"] = url;
        }
        
        for (const auto& [k, v] : headers) {
            req << k << ": " << v << "\r\n";
        }
        req << "User-Agent: " << user_agent << "\r\n";
        req << "Accept: */*\r\n";
        req << "Connection: close\r\n\r\n";
        
        // In production, this would use libcurl or similar
        // For demo, simulate with a simple response
        resp.status_code = 200;
        resp.body = "<html><body>Mock Response</body></html>";
        resp.headers["Content-Type"] = "text/html";
        
        return resp;
    }

    Response post(const std::string& url, 
                  const std::map<std::string, std::string>& headers) {
        Response resp{201, "", {}};
        resp.status_code = 201;
        resp.body = "Created";
        return resp;
    }
};

// ============================================================================
// Session Manager - Authentication handling
// ============================================================================

class SessionManager {
public:
    struct AuthState {
        std::string token;
        bool authenticated = false;
        int attempts = 0;
        double last_attempt_time = 0.0;
    };

private:
    std::map<std::string, AuthState> sessions;
    HttpClient client_;
    
public:
    bool authenticate(const TargetConfig& config) {
        if (config.auth_type == "basic") {
            // Basic auth - store credentials in session
            sessions[config.url].token = config.auth_token;
            sessions[config.url].authenticated = true;
            return true;
        } else if (config.auth_type == "bearer") {
            // Bearer token injection
            auto& sess = sessions[config.url];
            sess.token = config.auth_token;
            sess.authenticated = true;
            
            // Verify token with a probe request
            std::map<std::string, std::string> headers;
            if (!sess.token.empty()) {
                headers["Authorization"] = "Bearer " + sess.token;
            }
            
            auto resp = client_.get(config.url, headers);
            return resp.success();
        } else if (config.auth_type == "session") {
            // Session cookie handling
            sessions[config.url].authenticated = true;
            for (const auto& [k, v] : config.cookies) {
                sessions[config.url].token += k + "=" + v + "; ";
            }
            return true;
        }
        
        return false;
    }

    std::map<std::string, std::string> getAuthHeaders(const TargetConfig& config) {
        std::map<std::string, std::string> headers;
        
        auto it = sessions.find(config.url);
        if (it != sessions.end() && !it->second.token.empty()) {
            // Extract cookie string or auth header
            if (!config.auth_type.empty() && config.auth_type == "bearer") {
                headers["Authorization"] = "Bearer " + it->second.token;
            } else {
                headers["Cookie"] = it->second.token;
            }
        }
        
        // Add static headers from config
        for (const auto& [k, v] : config.headers) {
            headers[k] = v;
        }
        
        return headers;
    }

    void refreshSession(const TargetConfig& config) {
        if (config.auth_type == "session") {
            // Refresh session cookies
            for (const auto& [k, v] : config.cookies) {
                sessions[config.url].token += k + "=" + v + "; ";
            }
        }
    }
};

// ============================================================================
// Crawl State Machine - Core target management logic
// ============================================================================

class CrawlState {
public:
    enum class Status {
        New,           // Target discovered, not crawled yet
        Queued,        // Ready to crawl
        Crawling,      // Currently being processed
        Completed,     // Successfully finished
        Failed,        // Error during crawl
        Skipped,       // Excluded by rules or depth limit
    };

private:
    Status status = Status::New;
    int current_depth = 0;
    std::string last_url = "";
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    
public:
    void transition(Status new_status) {
        if (new_status == Status::Crawling && status != Status::New && 
            status != Status::Queued) {
            // Prevent duplicate crawling
            return;
        }
        
        start_time = std::chrono::steady_clock::now();
        status = new_status;
    }

    bool isReady() const {
        return status == Status::New || status == Status::Queued;
    }

    void incrementDepth() {
        current_depth++;
    }

    int getDepth() const {
        return current_depth;
    }

    std::string getStatusString() const {
        switch (status) {
            case Status::New: return "NEW";
            case Status::Queued: return "QUEUED";
            case Status::Crawling: return "CRAWLING";
            case Status::Completed: return "COMPLETED";
            case Status::Failed: return "FAILED";
            case Status::Skipped: return "SKIPPED";
            default: return "UNKNOWN";
        }
    }

    double getDuration() const {
        auto elapsed = std::chrono::duration<double>(end_time - start_time);
        return static_cast<double>(elapsed.count());
    }
};

// ============================================================================
// Crawler Engine - Rate-limited, backoff-aware traversal
// ============================================================================

class CrawlerEngine {
public:
    struct CrawlResult {
        std::string url;
        int depth = 0;
        bool success = false;
        std::vector<std::string> discovered_urls;
        double duration = 0.0;
        int http_status = 200;
    };

private:
    HttpClient client_;
    SessionManager session_mgr_;
    CrawlState state_;
    
    // Rate limiting with token bucket
    std::mutex rate_mutex;
    double tokens_available = 1.0;
    double token_rate = 1.0;
    double last_refill_time = 0.0;

public:
    void setRateLimit(double rate) {
        token_rate = rate;
        tokens_available = rate;
    }

    bool canProceed() {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - last_refill_time).count();
        
        // Refill tokens based on time passed
        tokens_available += elapsed * token_rate;
        if (tokens_available > 10.0) {
            tokens_available = 10.0;
        }
        
        last_refill_time = now;
        return tokens_available >= 1.0;
    }

    void consumeToken() {
        std::lock_guard<std::mutex> lock(rate_mutex);
        if (tokens_available > 0) {
            tokens_available -= 1.0;
        } else {
            // Exponential backoff on rate limit hit
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - last_refill_time).count();
            tokens_available += elapsed * token_rate;
            if (tokens_available > 1.0) {
                tokens_available = 1.0;
            }
        }
    }

    CrawlResult crawl(const TargetConfig& config, int max_depth) {
        CrawlResult result;
        
        // Initialize state
        state_.transition(CrawlState::Status::Queued);
        result.url = config.url;
        result.depth = 0;
        result.success = true;
        
        std::map<std::string, std::string> headers = session_mgr_.getAuthHeaders(config);
        
        // Initial request to verify connectivity and auth
        auto resp = client_.get(config.url, headers);
        result.http_status = resp.status_code;
        
        if (resp.success()) {
            state_.transition(CrawlState::Status::Crawling);
            
            // Extract discovered URLs from response
            std::regex url_regex(R"((https?://[^\s<>"']{3,})|(\./[^\"\s]{2,}))");
            auto matches = std::sregex_iterator(resp.body.begin(), 
                                                resp.body.end(), 
                                                url_regex);
            
            while (matches != std::sregex_iterator()) {
                result.discovered_urls.push_back(matches->str());
                matches++;
            }
        } else {
            state_.transition(CrawlState::Status::Failed);
            result.success = false;
        }
        
        // Apply depth limit
        if (result.depth < max_depth) {
            state_.incrementDepth();
        }
        
        return result;
    }

    void reset() {
        tokens_available = token_rate;
        last_refill_time = std::chrono::steady_clock::now();
        state_ = CrawlState{};
    }
};

// ============================================================================
// Target Manager - Main orchestrator class
// ============================================================================

class TargetManager {
public:
    struct TargetInfo {
        std::string id;
        TargetConfig config;
        CrawlState crawl_state;
        bool authenticated = false;
        int attempts = 0;
        double last_success_time = 0.0;
    };

private:
    DASTConfig main_config;
    SessionManager session_mgr_;
    CrawlerEngine crawler_;
    
    std::vector<TargetInfo> targets;
    std::mutex targets_mutex;
    
    // Deduplication for SARIF output
    std::set<std::string> seen_urls;
    std::mutex dedup_mutex;

public:
    TargetManager() : crawler_() {
        crawler_.setRateLimit(main_config.global_rate_limit);
    }

    void loadConfig(const std::string& config_path) {
        // Parse JSON configuration file
        std::ifstream file(config_path);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open config: " + config_path);
        }

        // Simple JSON parser for our specific format
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();

        // Extract targets array and count
        size_t start = content.find("\"targets\"");
        if (start == std::string::npos) {
            throw std::runtime_error("No targets found in config");
        }

        auto end_bracket = content.find(']', start);
        if (end_bracket == std::string::npos) {
            throw std::runtime_error("Malformed targets array");
        }

        // Parse individual target objects
        size_t pos = start + 8;
        while (pos < end_bracket && main_config.num_targets < 4) {
            if (content[pos] == '{') {
                auto obj_end = content.find('}', pos);
                if (obj_end != std::string::npos) {
                    std::string obj_str = content.substr(pos + 1, obj_end - pos - 2);
                    
                    // Extract fields using regex patterns
                    TargetConfig tc;
                    tc.name = extractString(obj_str, "\"name\"");
                    tc.url = extractString(obj_str, "\"url\"");
                    tc.max_depth = extractInt(obj_str, "\"max_depth\"", 3);
                    tc.rate_limit = extractDouble(obj_str, "\"rate_limit\"", 1.0);
                    
                    // Extract headers
                    auto hdr_start = obj_str.find("\"headers\"");
                    if (hdr_start != std::string::npos) {
                        auto hdr_end = obj_str.find('}', hdr_start);
                        tc.headers = parseHeaders(obj_str.substr(hdr_start, hdr_end - hdr_start + 1));
                    }

                    // Extract cookies
                    auto cks_start = obj_str.find("\"cookies\"");
                    if (cks_start != std::string::npos) {
                        auto cks_end = obj_str.find('}', cks_start);
                        tc.cookies = parseCookies(obj_str.substr(cks_start, cks_end - cks_start + 1));
                    }

                    // Extract auth type and token
                    auto auth_type_pos = obj_str.find("\"auth_type\"");
                    if (auth_type_pos != std::string::npos) {
                        tc.auth_type = extractString(obj_str.substr(auth_type_pos, 
                            obj_str.length() - auth_type_pos), "\"auth_type\"");
                    }

                    auto auth_token_pos = obj_str.find("\"auth_token\"");
                    if (auth_token_pos != std::string::npos) {
                        tc.auth_token = extractString(obj_str.substr(auth_token_pos, 
                            obj_str.length() - auth_token_pos), "\"auth_token\"");
                    }

                    // Extract redirect settings
                    auto rd_start = obj_str.find("\"follow_redirects\"");
                    if (rd_start != std::string::npos) {
                        tc.follow_redirects = extractBool(obj_str.substr(rd_start, 
                            obj_str.length() - rd_start), "\"follow_redirects\"", true);
                    }

                    // Extract redirect max
                    auto rd_max_pos = obj_str.find("\"redirect_max\"");
                    if (rd_max_pos != std::string::npos) {
                        tc.redirect_max = extractInt(obj_str.substr(rd_max_pos, 
                            obj_str.length() - rd_max_pos), "\"redirect_max\"", 5);
                    }

                    main_config.targets[main_config.num_targets] = tc;
                    main_config.num_targets++;
                    
                    // Initialize target info
                    TargetInfo ti;
                    ti.id = "target_" + std