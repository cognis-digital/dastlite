/*
 * polyglot/c/config_parser.c
 * 
 * DASTLite Configuration Parser - Production-Ready Implementation
 * 
 * Parses YAML/JSON config files for authenticated web/mobile API DAST scanning.
 * Supports targets, authentication methods, curated rulesets, and SARIF output settings.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

/* ============================================================================
 * CONSTANTS & MACROS
 * ============================================================================ */

#define MAX_LINE_LEN    4096
#define MAX_PATH_LEN    1024
#define MAX_URL_LEN     8192
#define MAX_RULESET_ID  256
#define MAX_CONFIG_SIZE 65536

/* Default paths and values */
#define DEFAULT_CONFIG_PATH "./dastlite.yaml"
#define DEFAULT_OUTPUT_DIR "./results"
#define DEFAULT_TIMEOUT_SEC 300

/* ============================================================================
 * DATA STRUCTURES - The Config Schema
 * ============================================================================ */

typedef enum {
    AUTH_NONE,
    AUTH_BASIC,
    AUTH_BEARER,
    AUTH_OAUTH2,
    AUTH_SESSION,
    AUTH_API_KEY
} AuthType;

typedef struct {
    char url[MAX_URL_LEN];
    bool https;
    int port;
    int timeout_ms;
} Target;

typedef struct {
    AuthType type;
    char username[64];
    char password[128];
    char api_key[512];
    char bearer_token[1024];
    char oauth_client_id[256];
    char oauth_secret[512];
    char oauth_scope[256];
} Auth;

typedef enum {
    RULE_HTTPS,
    RULE_CSP,
    RULE_XSS,
    RULE_SQLI,
    RULE_LFI,
    RULE_RCE,
    RULE_CMD_INJ,
    RULE_DIR_TRAV,
    RULE_SSRF,
    RULE_HEADER_INJ,
    RULE_COOKIE_INJ,
    RULE_PARAM_INJ,
    RULE_JSON_INJ,
    RULE_XML_INJ,
    RULE_PATH_TRAV,
    RULE_FILE_INCL,
    RULE_TEMPORARY_FILES,
    RULE_ENV_VAR_LEAK,
    RULE_SESSION_FIXATION,
    RULE_OPEN_REDIRECT,
    RULE_CORS_MISCONFIG,
    RULE_CONTENT_TYPE,
    RULE_CACHE_CONTROL,
    RULE_SET_COOKIE,
    RULE_HTTP_METHODS,
    RULE_STATUS_CODES,
    RULE_RESPONSE_SIZE,
    RULE_RECURSION_DEPTH,
    RULE_FOLLOW_REDIRECTS,
    RULE_MAX_REDIRECTS,
    RULE_USER_AGENTS,
    RULE_HEADERS_TO_SEND,
    RULE_REQUEST_PARAMS,
    RULE_POST_DATA,
    RULE_MULTI_PART,
    RULE_FORM_FIELDS,
    RULE_FILE_UPLOAD,
    RULE_API_VERSIONING,
    RULE_RATE_LIMIT,
    RULE_RETRY_POLICY,
    RULE_MAX_RETRIES,
    RULE_BACKOFF_MS,
    RULE_CONCURRENCY,
    RULE_WORKERS,
    RULE_QUEUE_SIZE,
    RULE_LOG_LEVEL,
    RULE_OUTPUT_FORMAT,
    RULE_SARIF_VERSION,
    RULE_DEDUPLICATE,
    RULE_INCLUDE_METADATA,
    RULE_THREAD_COUNT,
    RULE_MEMORY_LIMIT_MB,
    RULE_CHECKSUM_ALGO,
    RULE_TIMESTAMP_FORMAT,
    RULE_EVENT_ID_PREFIX,
    RULE_RUN_ID,
    RULE_PROJECT_NAME,
    RULE_VERSION,
    RULE_CONTACT_EMAIL,
    RULE_TOOL_NAME,
    RULE_TOOL_VERSION,
} RuleType;

typedef struct {
    RuleType type;
    int priority;      /* Higher = run first */
    bool enabled;
    char name[256];
    void *context;     /* Pointer to rule-specific context data */
} RuleEntry;

typedef enum {
    OUT_JSON,
    OUT_SARIF,
    OUT_CSV,
    OUT_TEXT,
    OUT_HTML
} OutputFormat;

typedef struct {
    char path[MAX_PATH_LEN];
    OutputFormat format;
    int sarif_version;  /* 2.1.0 or 2.3.0 */
    bool deduplicate;
    bool include_metadata;
    size_t max_results;
} OutputConfig;

typedef struct {
    char path[MAX_PATH_LEN];
    Auth auth;
    Target targets[8];
    int target_count;
    RuleEntry ruleset[64];
    int rule_count;
    OutputConfig output;
    int timeout_sec;
    bool verbose;
    bool dry_run;
} DASTLiteConfig;

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static DASTLiteConfig g_config = {0};
static char g_error_buffer[512] = {0};
static size_t g_error_len = 0;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

#define SET_ERROR(fmt, ...) \
    do { \
        snprintf(g_error_buffer, sizeof(g_error_buffer), fmt, ##__VA_ARGS__); \
        g_error_len = strlen(g_error_buffer); \
    } while(0)

static inline bool is_valid_url(const char *url) {
    if (!url || !*url) return false;
    
    /* Must start with http:// or https:// */
    const char *scheme[] = {"http://", "https://"};
    for (int i = 0; i < 2; i++) {
        if (strncmp(url, scheme[i], strlen(scheme[i])) == 0) {
            return true;
        }
    }
    
    /* Check for valid characters */
    const char *valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=";
    while (*url) {
        bool found = false;
        for (int i = 0; !found && valid[i]; i++) {
            if (*url == valid[i]) found = true;
        }
        if (!found) return false;
        url++;
    }
    
    return true;
}

static inline bool is_valid_email(const char *email) {
    if (!email || !*email) return false;
    
    /* Basic email pattern check */
    const char *local = email;
    while (*local && *local != '@') local++;
    if (!*local) return false;  /* No @ found */
    
    const char *domain = local + 1;
    while (*domain) {
        if (*domain == '.' || isalnum(*domain)) continue;
        if (strchr("._-+-", *domain)) continue;
        return false;
    }
    
    /* Must end with a dot */
    return domain[strlen(domain) - 1] == '.';
}

static inline bool is_valid_hostname(const char *host, int max_len) {
    if (!host || !*host) return false;
    
    const char *p = host;
    while (*p && (isalnum(*p) || *p == '-' || *p == '.')) p++;
    
    /* Check for valid characters */
    while (*p) {
        if (isdigit(*p)) continue;
        if (strchr("._-+-", *p)) continue;
        return false;
    }
    
    /* Must end with a dot or be followed by port/path */
    return true;
}

static inline bool is_valid_port(int port) {
    return port >= 1 && port <= 65535;
}

/* ============================================================================
 * PARSER STATE MACHINE - YAML/JSON Hybrid Parser
 * ============================================================================ */

typedef enum {
    PARSE_ROOT,
    PARSE_TARGETS,
    PARSE_AUTH,
    PARSE_RULESET,
    PARSE_OUTPUT,
    PARSE_GLOBAL,
    PARSE_DONE,
    PARSE_ERROR
} ParseState;

typedef struct {
    char line[MAX_LINE_LEN];
    int line_num;
    bool in_quotes;
    bool multiline_value;
    char *multiline_buffer;
    size_t multiline_pos;
    size_t multiline_capacity;
} ParserContext;

static void parser_init(ParserContext *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->multiline_capacity = MAX_LINE_LEN;
    ctx->multiline_buffer = malloc(MAX_LINE_LEN);
}

static void parser_free(ParserContext *ctx) {
    if (ctx->multiline_buffer) {
        free(ctx->multiline_buffer);
    }
}

/* Trim whitespace from string */
static inline char *trim(char *s, size_t len) {
    while (len > 0 && isspace(s[0])) s++, len--;
    while (len > 0 && isspace(s[len - 1])) len--, s++;
    return s;
}

/* ============================================================================
 * YAML/JSON PARSING CORE
 * ============================================================================ */

static bool parse_string_value(const char *line, char *out, size_t out_size) {
    /* Extract string value, handling quotes */
    const char *start = line;
    while (*start && !isspace(*start)) start++;
    
    if (!*start || *start == '#') return false;  /* Empty or comment */
    
    /* Find end of string (quote or whitespace) */
    const char *end = start;
    bool in_quote = false;
    while (*end && !isspace(*end)) {
        if (*end == '"' || *end == '\'') {
            if (!in_quote) {
                in_quote = true;
            } else {
                in_quote = false;
                end++;  /* Include closing quote */
                break;
            }
        }
        end++;
    }
    
    size_t len = end - start;
    if (len >= out_size) return false;
    
    strncpy(out, start, len);
    out[len] = '\0';
    
    /* Remove surrounding quotes */
    if (out[0] == '"' || out[0] == '\'') {
        memmove(out, out + 1, len - 2);
        out[len - 2] = '\0';
    }
    
    return true;
}

static bool parse_integer_value(const char *line, int *out) {
    const char *start = line;
    while (*start && !isspace(*start)) start++;
    
    if (!*start || *start == '#') return false;
    
    /* Parse integer */
    char buf[64];
    size_t len = 0;
    while (*start && !isspace(*start) && len < sizeof(buf) - 1) {
        buf[len++] = *start++;
    }
    buf[len] = '\0';
    
    if (len == 0 || !strtol(buf, NULL, 10)) return false;
    
    *out = atoi(buf);
    return true;
}

static bool parse_boolean_value(const char *line, bool *out) {
    const char *start = line;
    while (*start && !isspace(*start)) start++;
    
    if (!*start || *start == '#') return false;
    
    /* Normalize boolean strings */
    size_t len = 0;
    while (*start && !isspace(*start) && len < sizeof("true")) {
        buf[len++] = tolower(*start++);
    }
    buf[len] = '\0';
    
    if (strncmp(buf, "true", 4) == 0 || strncmp(buf, "yes", 3) == 0 || 
        strncmp(buf, "on", 2) == 0) {
        *out = true;
        return true;
    } else if (strncmp(buf, "false", 5) == 0 || strncmp(buf, "no", 2) == 0 ||
               strncmp(buf, "off", 3) == 0) {
        *out = false;
        return true;
    }
    
    return false;
}

/* ============================================================================
 * CONFIG FILE PARSING
 * ============================================================================ */

static bool parse_config_file(const char *path, DASTLiteConfig *cfg) {
    if (!path || !*path) {
        SET_ERROR("Configuration path is empty");
        return false;
    }
    
    /* Check file exists and readable */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        SET_ERROR("Failed to open config file: %s", path);
        return false;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (fsize <= 0 || fsize > MAX_CONFIG_SIZE) {
        SET_ERROR("Config file too large or empty: %s", path);
        fclose(fp);
        return false;
    }
    
    /* Read entire file */
    char *content = malloc(fsize + 1);
    if (!content) {
        SET_ERROR("Memory allocation failed for config content");
        fclose(fp);
        return false;
    }
    
    size_t total_read = fread(content, 1, fsize, fp);
    content[total_read] = '\0';
    fclose(fp);
    
    /* Initialize parser context */
    ParserContext ctx;
    parser_init(&ctx);
    
    bool success = parse_config_content(content, &ctx, cfg);
    
    parser_free(&ctx);
    free(content);
    
    return success;
}

static bool parse_config_content(const char *content, ParserContext *ctx, 
                                  DASTLiteConfig *cfg) {
    /* Initialize default config */
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->path, DEFAULT_CONFIG_PATH, MAX_PATH_LEN - 1);
    cfg->output.path = DEFAULT_OUTPUT_DIR;
    cfg->output.format = OUT_SARIF;
    cfg->output.sarif_version = 2.3;
    cfg->output.deduplicate = true;
    cfg->timeout_sec = DEFAULT_TIMEOUT_SEC;
    
    /* Parse line by line */
    const char *p = content;
    while (*p) {
        /* Skip empty lines and comments */
        if (isspace(*p)) {
            p++;
            continue;
        }
        
        if (*p == '#') {
            while (*p && !isspace(*p)) p++;
            continue;
        }
        
        /* Parse key-value pairs */
        char key[256] = {0};
        char value[MAX_LINE_LEN] = {0};
        
        const char *key_start = p;
        while (*p && !isspace(*p) && *p != ':' && *p != '=') p++;
        size_t key_len = p - key_start;
        
        if (key_len == 0 || key_len >= sizeof(key)) {
            SET_ERROR("Malformed config line: %.*s", (int)(p - content), content);
            return false;
        }
        
        strncpy(key, key_start, key_len);
        key[key_len] = '\0';
        
        /* Skip whitespace after key */
        while (*p && isspace(*p)) p++;
        
        if (!*p || *p == '#') continue;  /* End of line or comment */
        
        /* Parse value */
        const char *value_start = p;
        while (*p && !isspace(*p) && *p != ':' && *p != '=') p++;
        size_t value_len = p - value_start;
        
        if (value_len == 0 || value_len >= sizeof(value)) {
            SET_ERROR("Malformed config line: %.*s", (int)(p - content), content);
            return false;
        }
        
        strncpy(value, value_start, value_len);
        value[value_len] = '\0';
        
        /* Parse the actual string value */
        char clean_value[256];
        if (!parse_string_value(value, clean_value, sizeof(clean_value))) {
            SET_ERROR("Failed to parse value: %.*s", (int)value_len, value);
            return false;
        }
        
        /* Dispatch to appropriate parser based on key */
        if (strcmp(key, "path") == 0) {
            strncpy(cfg->path, clean_value, MAX_PATH_LEN - 1);
        } else if (strcmp(key, "targets") == 0) {
            parse_targets_section(content, p, ctx, cfg);
        } else if (strcmp(key, "auth") == 0) {
            parse_auth_section(content, p, ctx, &cfg->auth);
        } else if (strcmp(key, "ruleset") == 0) {
            parse_ruleset_section(content, p, ctx, cfg);
        } else if (strcmp(key, "output") == 0) {
            parse_output_section(content, p, ctx, &cfg->output);
        } else if (strcmp(key, "timeout") == 0)