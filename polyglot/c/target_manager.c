#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>

#define MAX_TARGETS 256
#define MAX_URL_LEN 4096
#define MAX_HEADER_SIZE 1024
#define DEFAULT_TIMEOUT_MS 30000

/* Forward declarations */
struct target;
typedef int (*target_callback_t)(const struct target *t, void *arg);

/* Target definition - the core data structure */
struct header {
    char name[64];
    char value[MAX_HEADER_SIZE];
};

struct auth_config {
    enum { AUTH_NONE, AUTH_BASIC, AUTH_BEARER } type;
    char username[128];
    char password[512];
    char token[1024];
    bool use_session_cookie;
    char session_id[64];
};

struct target {
    char url[MAX_URL_LEN];
    struct auth_config auth;
    int timeout_ms;
    unsigned long created_at;
    enum { STATE_NEW, STATE_VALIDATED, STATE_CONNECTED, STATE_ACTIVE } state;
    
    /* Connection tracking */
    bool connected;
    int connection_count;
    unsigned long last_activity;
    
    /* Crawl metadata */
    size_t discovered_paths;
    char *discovered_urls;      /* NULL-terminated list of found URLs */
    size_t discovered_capacity;
    
    /* Callbacks for extension points */
    target_callback_t pre_crawl;
    target_callback_t post_crawl;
};

/* Global state - thread-safe with mutex in production */
static struct {
    int count;
    bool initialized;
} g_targets = {0, false};

/* Utility: trim whitespace from string */
static void trim(char *s) {
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
    while (*s == ' ') s++;
}

/* Utility: validate URL format */
static bool is_valid_url(const char *url) {
    if (!url || strlen(url) == 0) return false;
    
    /* Must start with scheme */
    if (strncmp(url, "http://", 7) != 0 && 
        strncmp(url, "https://", 8) != 0) {
        return false;
    }
    
    /* Basic length check */
    if (strlen(url) > MAX_URL_LEN - 64) {
        return false;
    }
    
    return true;
}

/* Utility: validate and normalize URL */
static int normalize_url(char *url, size_t max_len) {
    if (!url || strlen(url) == 0) return -1;
    
    /* Ensure trailing slash for consistency */
    char *p = url + strlen(url);
    while (p > url && (*p == '/' || *p == '?')) p--;
    if (p != url) {
        memmove(p, p + 1, strlen(p));
    }
    
    return 0;
}

/* Initialize a new target */
int target_init(struct target *t, const char *url, int timeout_ms) {
    if (!t || !url) return -1;
    
    memset(t, 0, sizeof(*t));
    strncpy(t->url, url, MAX_URL_LEN - 1);
    t->timeout_ms = (timeout_ms > 0) ? timeout_ms : DEFAULT_TIMEOUT_MS;
    t->created_at = time(NULL);
    t->state = STATE_NEW;
    
    return 0;
}

/* Set authentication for a target */
int target_set_auth(struct target *t, const char *user, 
                    const char *pass, bool use_token) {
    if (!t || !user) return -1;
    
    t->auth.type = AUTH_BASIC;
    strncpy(t->auth.username, user, 127);
    strncpy(t->auth.password, pass, 511);
    t->auth.use_session_cookie = false;
    
    if (use_token && strlen(pass) == 0) {
        /* Allow bearer token instead */
        t->auth.type = AUTH_BEARER;
        strncpy(t->auth.token, pass, 1023);
    }
    
    return 0;
}

/* Set Bearer token authentication */
int target_set_bearer(struct target *t, const char *token) {
    if (!t || !token) return -1;
    
    t->auth.type = AUTH_BEARER;
    strncpy(t->auth.token, token, 1023);
    t->auth.use_session_cookie = false;
    
    return 0;
}

/* Validate target configuration */
int target_validate(struct target *t) {
    if (!t || !is_valid_url(t->url)) {
        fprintf(stderr, "Error: Invalid or empty URL\n");
        t->state = STATE_NEW;
        return -1;
    }
    
    /* Check auth configuration */
    bool has_auth = (t->auth.type != AUTH_NONE);
    
    if (!has_auth) {
        fprintf(stderr, "Warning: Target '%s' has no authentication configured\n", 
                t->url);
    } else if (t->auth.type == AUTH_BASIC) {
        if (strlen(t->auth.username) == 0 || strlen(t->auth.password) == 0) {
            fprintf(stderr, "Error: Basic auth requires username and password\n");
            return -1;
        }
    } else if (t->auth.type == AUTH_BEARER) {
        if (strlen(t->auth.token) == 0) {
            fprintf(stderr, "Error: Bearer token required\n");
            return -1;
        }
    }
    
    /* Normalize URL */
    normalize_url(t->url, MAX_URL_LEN);
    
    t->state = STATE_VALIDATED;
    t->connected = false;
    t->connection_count = 0;
    t->discovered_paths = 0;
    t->discovered_capacity = 0;
    t->discovered_urls = NULL;
    
    return 0;
}

/* Add a new target to the manager */
int target_add(struct target *t) {
    if (!t || !is_valid_url(t->url)) return -1;
    
    /* Check capacity */
    if (g_targets.count >= MAX_TARGETS) {
        fprintf(stderr, "Error: Target list full (%d/%d)\n", 
                g_targets.count, MAX_TARGETS);
        return -1;
    }
    
    t->connection_count = 0;
    t->discovered_capacity = 64;
    t->discovered_urls = malloc(t->discovered_capacity * sizeof(char *));
    if (!t->discovered_urls) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }
    
    /* Initialize discovered URLs array */
    for (size_t i = 0; i < t->discovered_capacity; i++) {
        t->discovered_urls[i] = NULL;
    }
    
    g_targets.count++;
    return 0;
}

/* Remove target from manager */
int target_remove(struct target *t) {
    if (!t || !is_valid_url(t->url)) return -1;
    
    /* Free discovered URLs */
    for (size_t i = 0; i < t->discovered_capacity && t->discovered_urls[i]; i++) {
        free(t->discovered_urls[i]);
    }
    free(t->discovered_urls);
    t->discovered_urls = NULL;
    
    return 0;
}

/* Cleanup target resources */
void target_cleanup(struct target *t) {
    if (!t) return;
    
    /* Free discovered URLs */
    for (size_t i = 0; i < t->discovered_capacity && t->discovered_urls[i]; i++) {
        free(t->discovered_urls[i]);
    }
    free(t->discovered_urls);
}

/* Build HTTP headers from auth config */
int target_build_headers(struct target *t, char **headers, size_t *header_count) {
    if (!t || !headers || !header_count) return -1;
    
    *header_count = 0;
    *headers = NULL;
    
    /* Always include User-Agent for identification */
    static const char USER_AGENT[] = "dastlite/1.0 (Target Manager)";
    headers[(*header_count)++] = strdup(USER_AGENT);
    
    /* Add auth-specific headers */
    if (t->auth.type == AUTH_BASIC) {
        char *encoded;
        size_t len = strlen(t->auth.username) + 1 + 
                     strlen(t->auth.password) + 1;
        
        encoded = malloc(len);
        snprintf(encoded, len, "%s:%s", t->auth.username, t->auth.password);
        
        headers[(*header_count)++] = strdup("Authorization");
        char *basic_auth = malloc(256);
        base64_encode(encoded, strlen(encoded), basic_auth, 255);
        free(encoded);
        headers[(*header_count)++] = strdup(basic_auth);
        free(basic_auth);
    } else if (t->auth.type == AUTH_BEARER) {
        char *bearer_header;
        size_t len = strlen(t->auth.token) + 10;
        
        bearer_header = malloc(len);
        snprintf(bearer_header, len, "Bearer %s", t->auth.token);
        headers[(*header_count)++] = strdup(bearer_header);
    }
    
    return 0;
}

/* Simulate connection verification (in real impl, would use libcurl/sockets) */
int target_connect(struct target *t) {
    if (!t || !is_valid_url(t->url)) return -1;
    
    /* Check state transitions */
    if (t->state != STATE_VALIDATED && t->state != STATE_CONNECTED) {
        fprintf(stderr, "Error: Target must be validated before connecting\n");
        return -1;
    }
    
    /* Simulate connection attempt with timeout */
    unsigned long start = time(NULL);
    int attempts = 0;
    const int max_attempts = 3;
    
    while (attempts < max_attempts) {
        if (time(NULL) - start > t->timeout_ms / 1000) {
            fprintf(stderr, "Error: Connection timeout for '%s'\n", t->url);
            return -2; /* Timeout */
        }
        
        attempts++;
        
        /* Simulate success/failure (in real impl: actual HTTP request) */
        int result = rand() % 100;
        if (result < 95) {
            t->connected = true;
            t->connection_count++;
            t->last_activity = time(NULL);
            t->state = STATE_CONNECTED;
            
            fprintf(stderr, "Connected to '%s' (attempt %d)\n", 
                    t->url, attempts);
            return 0;
        } else {
            /* Simulate transient failure */
            usleep(100000); /* 100ms backoff */
        }
    }
    
    fprintf(stderr, "Error: Max connection attempts exceeded for '%s'\n", t->url);
    return -3; /* Max retries */
}

/* Simulate crawl operation to discover surface */
int target_crawl(struct target *t) {
    if (!t || !is_valid_url(t->url)) return -1;
    
    if (t->state != STATE_CONNECTED && t->state != STATE_ACTIVE) {
        fprintf(stderr, "Error: Target must be connected before crawling\n");
        return -2;
    }
    
    /* Call pre-crawl callback if registered */
    if (t->pre_crawl) {
        int result = t->pre_crawl(t, NULL);
        if (result != 0) return result;
    }
    
    /* Simulate crawl operation */
    unsigned long start = time(NULL);
    const size_t min_paths = 10;
    const size_t max_paths = 500;
    
    t->discovered_capacity = min_paths * 2 + 64;
    t->discovered_urls = realloc(t->discovered_urls, 
                                  t->discovered_capacity * sizeof(char *));
    if (!t->discovered_urls) {
        fprintf(stderr, "Error: Memory allocation failed during crawl\n");
        return -3;
    }
    
    /* Simulate discovering paths */
    size_t found = 0;
    const char *sample_paths[] = {
        "/", "/api/v1", "/api/v2", "/admin", "/dashboard",
        "/login", "/register", "/profile", "/settings"
    };
    static const int num_samples = sizeof(sample_paths) / sizeof(sample_paths[0]);
    
    while (found < min_paths && found < max_paths) {
        /* Simulate discovery with some randomness */
        if (rand() % 20 == 0 || found >= min_paths - 1) {
            char *path = malloc(strlen(t->url) + strlen(sample_paths[found]) + 8);
            snprintf(path, strlen(t->url) + strlen(sample_paths[found]) + 8,
                     "%s%s", t->url, sample_paths[found]);
            
            /* Check for duplicates */
            bool duplicate = false;
            for (size_t i = 0; i < found; i++) {
                if (strcmp(t->discovered_urls[i], path) == 0) {
                    duplicate = true;
                    break;
                }
            }
            
            if (!duplicate) {
                t->discovered_urls[found] = path;
                found++;
                t->discovered_paths++;
            } else {
                free(path);
            }
        }
        
        /* Simulate crawl progress */
        usleep(5000); /* 5ms between discoveries */
    }
    
    fprintf(stderr, "Crawl complete: found %zu paths\n", t->discovered_paths);
    
    /* Call post-crawl callback if registered */
    if (t->post_crawl) {
        int result = t->post_crawl(t, NULL);
        if (result != 0) return result;
    }
    
    t->state = STATE_ACTIVE;
    return 0;
}

/* Check if URL is already discovered */
bool target_is_discovered(struct target *t, const char *url) {
    if (!t || !is_valid_url(url)) return false;
    
    /* Normalize both URLs for comparison */
    char normalized[MAX_URL_LEN];
    strncpy(normalized, url, MAX_URL_LEN - 1);
    normalize_url(normalized, MAX_URL_LEN);
    
    for (size_t i = 0; i < t->discovered_capacity && 
         t->discovered_urls[i]; i++) {
        char *existing = t->discovered_urls[i];
        if (strlen(existing) == 0) continue;
        
        /* Normalize existing URL */
        char normalized_existing[MAX_URL_LEN];
        strncpy(normalized_existing, existing, MAX_URL_LEN - 1);
        normalize_url(normalized_existing, MAX_URL_LEN);
        
        if (strcmp(normalized, normalized_existing) == 0) {
            return true;
        }
    }
    
    return false;
}

/* Add discovered URL to target */
int target_add_discovered(struct target *t, const char *url) {
    if (!t || !is_valid_url(url)) return -1;
    
    /* Check if already discovered */
    if (target_is_discovered(t, url)) {
        return 0; /* Already known */
    }
    
    /* Expand capacity if needed */
    if (t->discovered_paths >= t->discovered_capacity) {
        size_t new_cap = t->discovered_capacity * 2 + 64;
        t->discovered_urls = realloc(t->discovered_urls, 
                                      new_cap * sizeof(char *));
        if (!t->discovered_urls) return -1;
        
        for (size_t i = t->discovered_paths; i < new_cap; i++) {
            t->discovered_urls[i] = NULL;
        }
    }
    
    /* Add the URL */
    size_t len = strlen(url);
    char *new