#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "config.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char key[64];
} yaml_stack_item;

static void set_err(char *err, size_t err_len, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void set_err(char *err, size_t err_len, const char *fmt, ...) {
    if (err_len == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

static void site_defaults(rpsiod_site_config *site) {
    memset(site, 0, sizeof(*site));
    site->enabled = true;
    rpsiod_safe_copy(site->serve_as, sizeof(site->serve_as), "http");
    rpsiod_safe_copy(site->listen_ip, sizeof(site->listen_ip), "0.0.0.0");
    site->http_port = 80;
    site->https_port = 443;
    rpsiod_safe_copy(site->routing_type, sizeof(site->routing_type), "static");
    site->redirect_http_to_https = false;
    site->redirect_www_enabled = false;
    rpsiod_safe_copy(site->redirect_www_mode, sizeof(site->redirect_www_mode), "apexToWww");
    site->redirect_www_status = 301;
    site->ssl_enabled = false;
    rpsiod_safe_copy(site->ssl_mode, sizeof(site->ssl_mode), "auto");
    rpsiod_safe_copy(site->ssl_provider, sizeof(site->ssl_provider), "letsEncrypt");
    rpsiod_safe_copy(site->ssl_challenge, sizeof(site->ssl_challenge), "http");
    site->ssl_renew_before_sec = 30 * 86400;
    site->static_root_fd = -1;
    for (size_t i = 0; i < RPSIOD_OPEN_FILE_CACHE_MAX; i++) {
        site->open_file_cache[i].fd = -1;
    }
    site->directory_listing = false;
    site->maintenance_status = 503;
    site->max_body_size = 25ULL * 1024ULL * 1024ULL;
    site->hide_server_header = true;
    site->allow_symlinks = false;
    site->php_enabled = false;
    rpsiod_safe_copy(site->php_handler_type, sizeof(site->php_handler_type), "socket");
    rpsiod_safe_copy(site->php_socket, sizeof(site->php_socket), "/run/php/php-fpm.sock");
    rpsiod_safe_copy(site->php_host, sizeof(site->php_host), "127.0.0.1");
    site->php_port = 9000;
    site->php_allow_path_info = false;
    site->php_connect_timeout_sec = 5;
    site->php_read_timeout_sec = 30;
    site->php_write_timeout_sec = 30;
    site->php_max_body_size = 25ULL * 1024ULL * 1024ULL;
    site->php_max_execution_time_sec = 60;
    site->rate_limit_enabled = false;
    site->rate_limit_requests = 100;
    site->rate_limit_window_sec = 60;
    site->compression_enabled = false;
    site->compression_gzip = false;
    site->compression_br = false;
    site->compression_minimum_size = 1024;
    site->cache_enabled = false;
    rpsiod_safe_copy(site->proxy_scheme, sizeof(site->proxy_scheme), "http");
    site->proxy_port = 3000;
    site->proxy_websocket = false;
    site->proxy_pass_host = true;
    site->proxy_real_ip = true;
    site->proxy_forwarded_for = true;
    site->proxy_forwarded_proto = true;
    site->proxy_connect_timeout_sec = 5;
    site->proxy_read_timeout_sec = 30;
    site->proxy_write_timeout_sec = 30;
    site->proxy_health_enabled = false;
    rpsiod_safe_copy(site->proxy_health_path, sizeof(site->proxy_health_path), "/health");
    rpsiod_safe_copy(site->allowed_methods[site->allowed_method_count++], 16, "GET");
    rpsiod_safe_copy(site->allowed_methods[site->allowed_method_count++], 16, "HEAD");
    site->access_log.enabled = false;
    site->error_log.enabled = false;
    site->access_log.fd = -1;
    site->error_log.fd = -1;
}

void rpsiod_config_defaults(rpsiod_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    rpsiod_safe_copy(cfg->name, sizeof(cfg->name), "rpsiod");
    rpsiod_safe_copy(cfg->environment, sizeof(cfg->environment), "production");
    rpsiod_safe_copy(cfg->linux_user, sizeof(cfg->linux_user), "rpsiod");
    rpsiod_safe_copy(cfg->linux_group, sizeof(cfg->linux_group), "rpsiod");
    rpsiod_safe_copy(cfg->pid_file, sizeof(cfg->pid_file), "/run/rpsiod/rpsiod.pid");
    cfg->reuse_port = true;
    cfg->tcp_fast_open = true;
    cfg->backlog = 4096;
    cfg->open_files = 1048576;
    cfg->max_processes = 4096;
    cfg->workers_auto = true;
    cfg->workers = 1;
    cfg->max_connections = 50000;
    cfg->keep_alive_enabled = true;
    cfg->keep_alive_timeout_sec = 30;
    cfg->keep_alive_max_requests = 1000;
    cfg->request_header_buffer = 16 * 1024;
    cfg->response_buffer = 64 * 1024;
    cfg->sendfile_enabled = true;
    cfg->read_ahead_enabled = true;
    cfg->open_file_cache_enabled = true;
    cfg->open_file_cache_max = 64;
    cfg->hide_version = true;
    cfg->drop_privileges = true;
    cfg->prevent_core_dumps = true;
    rpsiod_safe_copy(cfg->logging_level, sizeof(cfg->logging_level), "info");
    rpsiod_safe_copy(cfg->logging_format, sizeof(cfg->logging_format), "text");
    cfg->access_log.enabled = true;
    cfg->access_log.fd = -1;
    rpsiod_safe_copy(cfg->access_log.path, sizeof(cfg->access_log.path), "/var/log/rpsiod/access.log");
    cfg->error_log.enabled = true;
    cfg->error_log.fd = -1;
    rpsiod_safe_copy(cfg->error_log.path, sizeof(cfg->error_log.path), "/var/log/rpsiod/error.log");
    cfg->benchmarks_enabled = true;
    rpsiod_safe_copy(cfg->benchmarks_ip, sizeof(cfg->benchmarks_ip), "127.0.0.1");
    cfg->benchmarks_port = 9191;
    rpsiod_safe_copy(cfg->benchmarks_storage_path, sizeof(cfg->benchmarks_storage_path), "/var/cache/rpsiod/benchmarks");
    rpsiod_safe_copy(cfg->server_file, sizeof(cfg->server_file), "/etc/rpsiod/server.yml");
    rpsiod_safe_copy(cfg->sites_file, sizeof(cfg->sites_file), "/etc/rpsiod/sites.yml");
    cfg->chroot_enabled = false;
}

static void strip_comment(char *line) {
    bool quoted = false;
    char quote = '\0';
    for (char *p = line; *p != '\0'; p++) {
        if ((*p == '\'' || *p == '"') && (p == line || p[-1] != '\\')) {
            if (!quoted) {
                quoted = true;
                quote = *p;
            } else if (*p == quote) {
                quoted = false;
            }
        }
        if (*p == '#' && !quoted) {
            *p = '\0';
            return;
        }
    }
}

static int indent_level(const char *line) {
    int spaces = 0;
    while (*line == ' ') {
        spaces++;
        line++;
    }
    return spaces / 4;
}

static bool split_key_value(char *line, char *key, size_t key_len, char *value, size_t value_len) {
    char *colon = strchr(line, ':');
    if (colon == NULL) {
        return false;
    }
    *colon = '\0';
    rpsiod_safe_copy(key, key_len, line);
    rpsiod_safe_copy(value, value_len, colon + 1);
    rpsiod_trim(key);
    rpsiod_trim(value);
    return key[0] != '\0';
}

static void stack_set(yaml_stack_item *stack, int level, const char *key) {
    if (level < 0 || level >= 32) {
        return;
    }
    rpsiod_safe_copy(stack[level].key, sizeof(stack[level].key), key);
    for (int i = level + 1; i < 32; i++) {
        stack[i].key[0] = '\0';
    }
}

static bool path_has(yaml_stack_item *stack, int max_level, const char *key) {
    for (int i = 0; i <= max_level && i < 32; i++) {
        if (strcmp(stack[i].key, key) == 0) {
            return true;
        }
    }
    return false;
}

static bool parent_is(yaml_stack_item *stack, int level, const char *key) {
    if (level <= 0 || level - 1 >= 32) {
        return false;
    }
    return strcmp(stack[level - 1].key, key) == 0;
}

static long parse_long(const char *value, long fallback) {
    char *end = NULL;
    long n = strtol(value, &end, 10);
    return end == value ? fallback : n;
}

static void parse_fail(rpsiod_config *cfg, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void parse_fail(rpsiod_config *cfg, const char *fmt, ...) {
    if (cfg->parse_failed) {
        return;
    }
    cfg->parse_failed = true;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cfg->parse_error, sizeof(cfg->parse_error), fmt, ap);
    va_end(ap);
}

static bool parse_bool_strict(const char *value, bool *out) {
    if (rpsiod_streq_ci(value, "true") || rpsiod_streq_ci(value, "yes") || strcmp(value, "1") == 0) {
        *out = true;
        return true;
    }
    if (rpsiod_streq_ci(value, "false") || rpsiod_streq_ci(value, "no") || strcmp(value, "0") == 0) {
        *out = false;
        return true;
    }
    return false;
}

static void apply_bool_value(rpsiod_config *cfg, bool *target, const char *field, const char *value) {
    bool parsed = false;
    if (!parse_bool_strict(value, &parsed)) {
        parse_fail(cfg, "%s must be a boolean", field);
        return;
    }
    *target = parsed;
}

static bool parse_port_strict(const char *value, uint16_t *out) {
    char *end = NULL;
    errno = 0;
    long n = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || n < 1 || n > 65535) {
        return false;
    }
    *out = (uint16_t)n;
    return true;
}

static void apply_port_value(rpsiod_config *cfg, uint16_t *target, const char *field, const char *value) {
    uint16_t parsed = 0;
    if (!parse_port_strict(value, &parsed)) {
        parse_fail(cfg, "%s must be a TCP port between 1 and 65535", field);
        return;
    }
    *target = parsed;
}

static void apply_server_value(rpsiod_config *cfg, yaml_stack_item *stack, int level, const char *key, const char *value) {
    if (value[0] == '\0') {
        return;
    }
    if (strcmp(key, "name") == 0 && parent_is(stack, level, "server")) {
        rpsiod_safe_copy(cfg->name, sizeof(cfg->name), value);
    } else if (strcmp(key, "environment") == 0) {
        rpsiod_safe_copy(cfg->environment, sizeof(cfg->environment), value);
    } else if (strcmp(key, "user") == 0 && path_has(stack, level, "linux")) {
        rpsiod_safe_copy(cfg->linux_user, sizeof(cfg->linux_user), value);
    } else if (strcmp(key, "group") == 0 && path_has(stack, level, "linux")) {
        rpsiod_safe_copy(cfg->linux_group, sizeof(cfg->linux_group), value);
    } else if (strcmp(key, "pidFile") == 0) {
        rpsiod_safe_copy(cfg->pid_file, sizeof(cfg->pid_file), value);
    } else if (strcmp(key, "reusePort") == 0) {
        apply_bool_value(cfg, &cfg->reuse_port, "linux.sockets.reusePort", value);
    } else if (strcmp(key, "tcpFastOpen") == 0) {
        apply_bool_value(cfg, &cfg->tcp_fast_open, "linux.sockets.tcpFastOpen", value);
    } else if (strcmp(key, "backlog") == 0) {
        cfg->backlog = (int)parse_long(value, cfg->backlog);
    } else if (strcmp(key, "openFiles") == 0) {
        cfg->open_files = rpsiod_parse_size(value, cfg->open_files);
    } else if (strcmp(key, "maxProcesses") == 0) {
        cfg->max_processes = rpsiod_parse_size(value, cfg->max_processes);
    } else if (strcmp(key, "workers") == 0) {
        if (rpsiod_streq_ci(value, "auto")) {
            cfg->workers_auto = true;
        } else {
            cfg->workers_auto = false;
            cfg->workers = (int)parse_long(value, cfg->workers);
        }
    } else if (strcmp(key, "maxConnections") == 0) {
        cfg->max_connections = rpsiod_parse_size(value, cfg->max_connections);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "keepAlive")) {
        apply_bool_value(cfg, &cfg->keep_alive_enabled, "performance.keepAlive.enabled", value);
    } else if (strcmp(key, "timeout") == 0 && path_has(stack, level, "keepAlive")) {
        cfg->keep_alive_timeout_sec = rpsiod_parse_duration_sec(value, cfg->keep_alive_timeout_sec);
    } else if (strcmp(key, "maxRequests") == 0) {
        cfg->keep_alive_max_requests = (int)parse_long(value, cfg->keep_alive_max_requests);
    } else if (strcmp(key, "requestHeader") == 0) {
        cfg->request_header_buffer = (size_t)rpsiod_parse_size(value, cfg->request_header_buffer);
    } else if (strcmp(key, "response") == 0 && path_has(stack, level, "buffers")) {
        cfg->response_buffer = (size_t)rpsiod_parse_size(value, cfg->response_buffer);
    } else if (strcmp(key, "sendfile") == 0) {
        apply_bool_value(cfg, &cfg->sendfile_enabled, "performance.staticFiles.sendfile", value);
    } else if (strcmp(key, "readAhead") == 0) {
        apply_bool_value(cfg, &cfg->read_ahead_enabled, "performance.staticFiles.readAhead", value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "openFileCache")) {
        apply_bool_value(cfg, &cfg->open_file_cache_enabled, "performance.openFileCache.enabled", value);
    } else if ((strcmp(key, "maxFiles") == 0 || strcmp(key, "max") == 0) && path_has(stack, level, "openFileCache")) {
        uint64_t parsed = rpsiod_parse_size(value, cfg->open_file_cache_max);
        cfg->open_file_cache_max = parsed > RPSIOD_OPEN_FILE_CACHE_MAX ? RPSIOD_OPEN_FILE_CACHE_MAX : (size_t)parsed;
    } else if (strcmp(key, "hideVersion") == 0) {
        apply_bool_value(cfg, &cfg->hide_version, "security.hideVersion", value);
    } else if (strcmp(key, "dropPrivileges") == 0) {
        apply_bool_value(cfg, &cfg->drop_privileges, "security.dropPrivileges", value);
    } else if (strcmp(key, "preventCoreDumps") == 0) {
        apply_bool_value(cfg, &cfg->prevent_core_dumps, "security.preventCoreDumps", value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "chroot")) {
        apply_bool_value(cfg, &cfg->chroot_enabled, "security.chroot.enabled", value);
    } else if (strcmp(key, "path") == 0 && path_has(stack, level, "chroot")) {
        rpsiod_safe_copy(cfg->chroot_path, sizeof(cfg->chroot_path), value);
    } else if (strcmp(key, "level") == 0 && path_has(stack, level, "logging")) {
        rpsiod_safe_copy(cfg->logging_level, sizeof(cfg->logging_level), value);
    } else if (strcmp(key, "format") == 0 && path_has(stack, level, "logging")) {
        rpsiod_safe_copy(cfg->logging_format, sizeof(cfg->logging_format), value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "access")) {
        apply_bool_value(cfg, &cfg->access_log.enabled, "logging.access.enabled", value);
    } else if (strcmp(key, "path") == 0 && path_has(stack, level, "access")) {
        rpsiod_safe_copy(cfg->access_log.path, sizeof(cfg->access_log.path), value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "error")) {
        apply_bool_value(cfg, &cfg->error_log.enabled, "logging.error.enabled", value);
    } else if (strcmp(key, "path") == 0 && path_has(stack, level, "error")) {
        rpsiod_safe_copy(cfg->error_log.path, sizeof(cfg->error_log.path), value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "benchmarks")) {
        apply_bool_value(cfg, &cfg->benchmarks_enabled, "benchmarks.enabled", value);
    } else if (strcmp(key, "ip") == 0 && path_has(stack, level, "benchmarks")) {
        rpsiod_safe_copy(cfg->benchmarks_ip, sizeof(cfg->benchmarks_ip), value);
    } else if (strcmp(key, "port") == 0 && path_has(stack, level, "benchmarks")) {
        apply_port_value(cfg, &cfg->benchmarks_port, "benchmarks.listen.port", value);
    } else if (strcmp(key, "path") == 0 && path_has(stack, level, "storage")) {
        rpsiod_safe_copy(cfg->benchmarks_storage_path, sizeof(cfg->benchmarks_storage_path), value);
    } else if (strcmp(key, "sitesFile") == 0) {
        rpsiod_safe_copy(cfg->sites_file, sizeof(cfg->sites_file), value);
    }
}

static int parse_server_file(rpsiod_config *cfg, const char *path, char *err, size_t err_len) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        set_err(err, err_len, "failed to open %s: %s", path, strerror(errno));
        return -1;
    }
    yaml_stack_item stack[32] = {0};
    char raw[4096];
    int line_no = 0;
    while (fgets(raw, sizeof(raw), fp) != NULL) {
        line_no++;
        strip_comment(raw);
        int level = indent_level(raw);
        char *line = raw;
        while (*line == ' ') {
            line++;
        }
        rpsiod_trim(line);
        if (line[0] == '\0') {
            continue;
        }
        char key[128];
        char value[1024];
        if (!split_key_value(line, key, sizeof(key), value, sizeof(value))) {
            fclose(fp);
            set_err(err, err_len, "%s:%d: expected key/value", path, line_no);
            return -1;
        }
        apply_server_value(cfg, stack, level, key, value);
        if (cfg->parse_failed) {
            fclose(fp);
            set_err(err, err_len, "%s:%d: %s", path, line_no, cfg->parse_error);
            return -1;
        }
        stack_set(stack, level, key);
    }
    fclose(fp);
    return 0;
}

static void append_string(char arr[][256], size_t *count, size_t max, const char *value) {
    if (*count < max) {
        rpsiod_safe_copy(arr[*count], 256, value);
        (*count)++;
    }
}

static void append_small_string(char arr[][128], size_t *count, size_t max, const char *value) {
    if (*count < max) {
        rpsiod_safe_copy(arr[*count], 128, value);
        (*count)++;
    }
}

static void append_method(rpsiod_site_config *site, const char *value) {
    if (site->allowed_method_count < RPSIOD_MAX_METHODS) {
        rpsiod_safe_copy(site->allowed_methods[site->allowed_method_count++], 16, value);
    }
}

static void append_blocked(rpsiod_site_config *site, const char *value) {
    if (site->blocked_direct_access_count < RPSIOD_MAX_BLOCKED) {
        rpsiod_safe_copy(site->blocked_direct_access[site->blocked_direct_access_count++], 128, value);
    }
}

static void append_header_remove(rpsiod_site_config *site, const char *value) {
    if (site->headers_remove_count < RPSIOD_MAX_HEADER_REMOVES) {
        rpsiod_safe_copy(site->headers_remove[site->headers_remove_count++], 128, value);
    }
}

static void append_header_add(rpsiod_site_config *site, const char *key, const char *value) {
    if (site->headers_add_count < RPSIOD_MAX_HEADERS) {
        rpsiod_safe_copy(site->headers_add[site->headers_add_count].name, 128, key);
        rpsiod_safe_copy(site->headers_add[site->headers_add_count].value, 512, value);
        site->headers_add_count++;
    }
}

typedef bool (*site_list_match_fn)(yaml_stack_item *stack, int level);
typedef void (*site_list_apply_fn)(rpsiod_config *cfg, rpsiod_site_config *site, const char *value);

typedef struct {
    site_list_match_fn matches;
    site_list_apply_fn apply;
} site_list_rule;

static bool list_parent_domains(yaml_stack_item *stack, int level) {
    return parent_is(stack, level, "domains");
}

static bool list_parent_index(yaml_stack_item *stack, int level) {
    return parent_is(stack, level, "index");
}

static bool list_parent_allowed_methods(yaml_stack_item *stack, int level) {
    return parent_is(stack, level, "allowedMethods");
}

static bool list_parent_block_direct_access(yaml_stack_item *stack, int level) {
    return parent_is(stack, level, "blockDirectAccess");
}

static bool list_headers_remove(yaml_stack_item *stack, int level) {
    return parent_is(stack, level, "remove") && path_has(stack, level, "headers");
}

static bool list_compression_algorithms(yaml_stack_item *stack, int level) {
    return parent_is(stack, level, "algorithms") && path_has(stack, level, "compression");
}

static void apply_domain_value(rpsiod_config *cfg, rpsiod_site_config *site, const char *value) {
    (void)cfg;
    append_string(site->domains, &site->domain_count, RPSIOD_MAX_DOMAINS, value);
}

static void apply_index_value(rpsiod_config *cfg, rpsiod_site_config *site, const char *value) {
    (void)cfg;
    append_small_string(site->indexes, &site->index_count, RPSIOD_MAX_INDEXES, value);
}

static void apply_method_value(rpsiod_config *cfg, rpsiod_site_config *site, const char *value) {
    (void)cfg;
    append_method(site, value);
}

static void apply_blocked_value(rpsiod_config *cfg, rpsiod_site_config *site, const char *value) {
    (void)cfg;
    append_blocked(site, value);
}

static void apply_header_remove_value(rpsiod_config *cfg, rpsiod_site_config *site, const char *value) {
    (void)cfg;
    append_header_remove(site, value);
}

static void apply_compression_algorithm(rpsiod_config *cfg, rpsiod_site_config *site, const char *value) {
    if (rpsiod_streq_ci(value, "gzip")) {
        site->compression_gzip = true;
    } else if (rpsiod_streq_ci(value, "br")) {
        site->compression_br = true;
    } else {
        parse_fail(cfg, "compression.algorithms entries must be gzip or br");
    }
}

static const site_list_rule SITE_LIST_RULES[] = {
    {list_parent_domains, apply_domain_value},
    {list_parent_index, apply_index_value},
    {list_parent_allowed_methods, apply_method_value},
    {list_parent_block_direct_access, apply_blocked_value},
    {list_headers_remove, apply_header_remove_value},
    {list_compression_algorithms, apply_compression_algorithm},
};

static void apply_site_list_value(rpsiod_config *cfg, rpsiod_site_config *site, yaml_stack_item *stack, int level, const char *value) {
    if (site == NULL || value[0] == '\0') {
        return;
    }
    for (size_t i = 0; i < sizeof(SITE_LIST_RULES) / sizeof(SITE_LIST_RULES[0]); i++) {
        if (SITE_LIST_RULES[i].matches(stack, level)) {
            SITE_LIST_RULES[i].apply(cfg, site, value);
            return;
        }
    }
}

static void apply_site_value(rpsiod_config *cfg, rpsiod_site_config *site, yaml_stack_item *stack, int level, const char *key, const char *value) {
    if (site == NULL || value[0] == '\0') {
        return;
    }
    if (strcmp(key, "name") == 0) {
        rpsiod_safe_copy(site->name, sizeof(site->name), value);
    } else if (strcmp(key, "enabled") == 0 && level == 2) {
        apply_bool_value(cfg, &site->enabled, "site.enabled", value);
    } else if (strcmp(key, "serveAs") == 0) {
        rpsiod_safe_copy(site->serve_as, sizeof(site->serve_as), value);
    } else if (strcmp(key, "ip") == 0 && path_has(stack, level, "listen")) {
        rpsiod_safe_copy(site->listen_ip, sizeof(site->listen_ip), value);
    } else if (strcmp(key, "http") == 0 && path_has(stack, level, "ports")) {
        apply_port_value(cfg, &site->http_port, "listen.ports.http", value);
    } else if (strcmp(key, "https") == 0 && path_has(stack, level, "ports")) {
        apply_port_value(cfg, &site->https_port, "listen.ports.https", value);
    } else if (strcmp(key, "type") == 0 && path_has(stack, level, "routing")) {
        rpsiod_safe_copy(site->routing_type, sizeof(site->routing_type), value);
    } else if (strcmp(key, "httpToHttps") == 0 && path_has(stack, level, "redirects")) {
        apply_bool_value(cfg, &site->redirect_http_to_https, "redirects.httpToHttps", value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "www") && path_has(stack, level, "redirects")) {
        apply_bool_value(cfg, &site->redirect_www_enabled, "redirects.www.enabled", value);
    } else if (strcmp(key, "mode") == 0 && path_has(stack, level, "www") && path_has(stack, level, "redirects")) {
        rpsiod_safe_copy(site->redirect_www_mode, sizeof(site->redirect_www_mode), value);
    } else if (strcmp(key, "status") == 0 && path_has(stack, level, "www") && path_has(stack, level, "redirects")) {
        site->redirect_www_status = (int)parse_long(value, site->redirect_www_status);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "ssl")) {
        apply_bool_value(cfg, &site->ssl_enabled, "ssl.enabled", value);
    } else if (strcmp(key, "mode") == 0 && path_has(stack, level, "ssl")) {
        rpsiod_safe_copy(site->ssl_mode, sizeof(site->ssl_mode), value);
    } else if (strcmp(key, "provider") == 0 && path_has(stack, level, "ssl")) {
        rpsiod_safe_copy(site->ssl_provider, sizeof(site->ssl_provider), value);
    } else if (strcmp(key, "email") == 0 && path_has(stack, level, "ssl")) {
        rpsiod_safe_copy(site->ssl_email, sizeof(site->ssl_email), value);
    } else if (strcmp(key, "storage") == 0 && path_has(stack, level, "ssl")) {
        rpsiod_safe_copy(site->ssl_storage, sizeof(site->ssl_storage), value);
    } else if (strcmp(key, "challenge") == 0 && path_has(stack, level, "ssl")) {
        rpsiod_safe_copy(site->ssl_challenge, sizeof(site->ssl_challenge), value);
    } else if (strcmp(key, "renewBefore") == 0 && path_has(stack, level, "ssl")) {
        site->ssl_renew_before_sec = rpsiod_parse_duration_sec(value, site->ssl_renew_before_sec);
    } else if (strcmp(key, "root") == 0 && path_has(stack, level, "static")) {
        rpsiod_safe_copy(site->static_root, sizeof(site->static_root), value);
    } else if (strcmp(key, "fallback") == 0 && path_has(stack, level, "static")) {
        rpsiod_safe_copy(site->fallback, sizeof(site->fallback), value);
    } else if (strcmp(key, "directoryListing") == 0) {
        apply_bool_value(cfg, &site->directory_listing, "static.directoryListing", value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "maintenance")) {
        apply_bool_value(cfg, &site->maintenance_enabled, "maintenance.enabled", value);
    } else if (strcmp(key, "status") == 0 && path_has(stack, level, "maintenance")) {
        site->maintenance_status = (int)parse_long(value, site->maintenance_status);
    } else if (strcmp(key, "page") == 0 && path_has(stack, level, "maintenance")) {
        rpsiod_safe_copy(site->maintenance_page, sizeof(site->maintenance_page), value);
    } else if (isdigit((unsigned char)key[0]) && path_has(stack, level, "pages")) {
        if (site->error_page_count < RPSIOD_MAX_ERROR_PAGES) {
            site->error_pages[site->error_page_count].code = (int)parse_long(key, 0);
            rpsiod_safe_copy(site->error_pages[site->error_page_count].path, 512, value);
            site->error_page_count++;
        }
    } else if (strcmp(key, "maxBodySize") == 0 && path_has(stack, level, "limits") && path_has(stack, level, "php")) {
        site->php_max_body_size = rpsiod_parse_size(value, site->php_max_body_size);
    } else if (strcmp(key, "maxBodySize") == 0) {
        site->max_body_size = rpsiod_parse_size(value, site->max_body_size);
    } else if (strcmp(key, "hideServerHeader") == 0) {
        apply_bool_value(cfg, &site->hide_server_header, "security.hideServerHeader", value);
    } else if (strcmp(key, "allowSymlinks") == 0) {
        apply_bool_value(cfg, &site->allow_symlinks, "security.allowSymlinks", value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "php")) {
        apply_bool_value(cfg, &site->php_enabled, "php.enabled", value);
    } else if (strcmp(key, "type") == 0 && path_has(stack, level, "handler") && path_has(stack, level, "php")) {
        rpsiod_safe_copy(site->php_handler_type, sizeof(site->php_handler_type), value);
    } else if (strcmp(key, "socket") == 0 && path_has(stack, level, "handler") && path_has(stack, level, "php")) {
        rpsiod_safe_copy(site->php_socket, sizeof(site->php_socket), value);
    } else if (strcmp(key, "host") == 0 && path_has(stack, level, "handler") && path_has(stack, level, "php")) {
        rpsiod_safe_copy(site->php_host, sizeof(site->php_host), value);
    } else if (strcmp(key, "port") == 0 && path_has(stack, level, "handler") && path_has(stack, level, "php")) {
        apply_port_value(cfg, &site->php_port, "php.handler.port", value);
    } else if (strcmp(key, "allowPathInfo") == 0 && path_has(stack, level, "security") && path_has(stack, level, "php")) {
        apply_bool_value(cfg, &site->php_allow_path_info, "php.security.allowPathInfo", value);
    } else if (strcmp(key, "connect") == 0 && path_has(stack, level, "timeouts") && path_has(stack, level, "php")) {
        site->php_connect_timeout_sec = rpsiod_parse_duration_sec(value, site->php_connect_timeout_sec);
    } else if (strcmp(key, "read") == 0 && path_has(stack, level, "timeouts") && path_has(stack, level, "php")) {
        site->php_read_timeout_sec = rpsiod_parse_duration_sec(value, site->php_read_timeout_sec);
    } else if (strcmp(key, "write") == 0 && path_has(stack, level, "timeouts") && path_has(stack, level, "php")) {
        site->php_write_timeout_sec = rpsiod_parse_duration_sec(value, site->php_write_timeout_sec);
    } else if (strcmp(key, "maxExecutionTime") == 0 && path_has(stack, level, "limits") && path_has(stack, level, "php")) {
        site->php_max_execution_time_sec = rpsiod_parse_duration_sec(value, site->php_max_execution_time_sec);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "rateLimit")) {
        apply_bool_value(cfg, &site->rate_limit_enabled, "limits.rateLimit.enabled", value);
    } else if (strcmp(key, "requests") == 0 && path_has(stack, level, "rateLimit")) {
        long requests = parse_long(value, (long)site->rate_limit_requests);
        site->rate_limit_requests = requests > 0 ? (uint32_t)requests : site->rate_limit_requests;
    } else if (strcmp(key, "window") == 0 && path_has(stack, level, "rateLimit")) {
        site->rate_limit_window_sec = rpsiod_parse_duration_sec(value, site->rate_limit_window_sec);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "compression")) {
        apply_bool_value(cfg, &site->compression_enabled, "compression.enabled", value);
    } else if (strcmp(key, "minimumSize") == 0 && path_has(stack, level, "compression")) {
        site->compression_minimum_size = rpsiod_parse_size(value, site->compression_minimum_size);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "cache")) {
        apply_bool_value(cfg, &site->cache_enabled, "cache.enabled", value);
    } else if (strcmp(key, "default") == 0 && path_has(stack, level, "cache")) {
        rpsiod_safe_copy(site->cache_default, sizeof(site->cache_default), value);
    } else if (path_has(stack, level, "headers") && path_has(stack, level, "add")) {
        append_header_add(site, key, value);
    } else if (strcmp(key, "scheme") == 0 && path_has(stack, level, "upstream") && path_has(stack, level, "proxy")) {
        rpsiod_safe_copy(site->proxy_scheme, sizeof(site->proxy_scheme), value);
    } else if (strcmp(key, "host") == 0 && path_has(stack, level, "upstream") && path_has(stack, level, "proxy")) {
        rpsiod_safe_copy(site->proxy_host, sizeof(site->proxy_host), value);
    } else if (strcmp(key, "port") == 0 && path_has(stack, level, "upstream") && path_has(stack, level, "proxy")) {
        apply_port_value(cfg, &site->proxy_port, "proxy.upstream.port", value);
    } else if (strcmp(key, "websocket") == 0 && path_has(stack, level, "proxy")) {
        apply_bool_value(cfg, &site->proxy_websocket, "proxy.websocket", value);
    } else if (strcmp(key, "passHost") == 0 && path_has(stack, level, "headers") && path_has(stack, level, "proxy")) {
        apply_bool_value(cfg, &site->proxy_pass_host, "proxy.headers.passHost", value);
    } else if (strcmp(key, "realIp") == 0 && path_has(stack, level, "headers") && path_has(stack, level, "proxy")) {
        apply_bool_value(cfg, &site->proxy_real_ip, "proxy.headers.realIp", value);
    } else if (strcmp(key, "forwardedFor") == 0 && path_has(stack, level, "headers") && path_has(stack, level, "proxy")) {
        apply_bool_value(cfg, &site->proxy_forwarded_for, "proxy.headers.forwardedFor", value);
    } else if (strcmp(key, "forwardedProto") == 0 && path_has(stack, level, "headers") && path_has(stack, level, "proxy")) {
        apply_bool_value(cfg, &site->proxy_forwarded_proto, "proxy.headers.forwardedProto", value);
    } else if (strcmp(key, "connect") == 0 && path_has(stack, level, "timeouts") && path_has(stack, level, "proxy")) {
        site->proxy_connect_timeout_sec = rpsiod_parse_duration_sec(value, site->proxy_connect_timeout_sec);
    } else if (strcmp(key, "read") == 0 && path_has(stack, level, "timeouts") && path_has(stack, level, "proxy")) {
        site->proxy_read_timeout_sec = rpsiod_parse_duration_sec(value, site->proxy_read_timeout_sec);
    } else if (strcmp(key, "write") == 0 && path_has(stack, level, "timeouts") && path_has(stack, level, "proxy")) {
        site->proxy_write_timeout_sec = rpsiod_parse_duration_sec(value, site->proxy_write_timeout_sec);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "healthCheck") && path_has(stack, level, "proxy")) {
        apply_bool_value(cfg, &site->proxy_health_enabled, "proxy.healthCheck.enabled", value);
    } else if (strcmp(key, "path") == 0 && path_has(stack, level, "healthCheck") && path_has(stack, level, "proxy")) {
        rpsiod_safe_copy(site->proxy_health_path, sizeof(site->proxy_health_path), value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "access")) {
        apply_bool_value(cfg, &site->access_log.enabled, "logging.access.enabled", value);
    } else if (strcmp(key, "path") == 0 && path_has(stack, level, "access")) {
        rpsiod_safe_copy(site->access_log.path, sizeof(site->access_log.path), value);
    } else if (strcmp(key, "enabled") == 0 && path_has(stack, level, "error")) {
        apply_bool_value(cfg, &site->error_log.enabled, "logging.error.enabled", value);
    } else if (strcmp(key, "path") == 0 && path_has(stack, level, "error")) {
        rpsiod_safe_copy(site->error_log.path, sizeof(site->error_log.path), value);
    }
}

static int parse_sites_file(rpsiod_config *cfg, const char *path, char *err, size_t err_len) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        set_err(err, err_len, "failed to open %s: %s", path, strerror(errno));
        return -1;
    }
    yaml_stack_item stack[32] = {0};
    rpsiod_site_config *site = NULL;
    char raw[4096];
    int line_no = 0;
    while (fgets(raw, sizeof(raw), fp) != NULL) {
        line_no++;
        strip_comment(raw);
        int level = indent_level(raw);
        char *line = raw;
        while (*line == ' ') {
            line++;
        }
        rpsiod_trim(line);
        if (line[0] == '\0') {
            continue;
        }
        if (line[0] == '-') {
            char *item = line + 1;
            rpsiod_trim(item);
            if (level == 1) {
                if (cfg->site_count >= RPSIOD_MAX_SITES) {
                    fclose(fp);
                    set_err(err, err_len, "%s:%d: too many sites", path, line_no);
                    return -1;
                }
                site = &cfg->sites[cfg->site_count++];
                site_defaults(site);
                if (item[0] != '\0') {
                    char key[128];
                    char value[1024];
                    if (split_key_value(item, key, sizeof(key), value, sizeof(value))) {
                        apply_site_value(cfg, site, stack, level + 1, key, value);
                        if (cfg->parse_failed) {
                            fclose(fp);
                            set_err(err, err_len, "%s:%d: %s", path, line_no, cfg->parse_error);
                            return -1;
                        }
                    }
                }
            } else {
                apply_site_list_value(cfg, site, stack, level, item);
                if (cfg->parse_failed) {
                    fclose(fp);
                    set_err(err, err_len, "%s:%d: %s", path, line_no, cfg->parse_error);
                    return -1;
                }
            }
            continue;
        }
        char key[128];
        char value[1024];
        if (!split_key_value(line, key, sizeof(key), value, sizeof(value))) {
            fclose(fp);
            set_err(err, err_len, "%s:%d: expected key/value", path, line_no);
            return -1;
        }
        apply_site_value(cfg, site, stack, level, key, value);
        if (cfg->parse_failed) {
            fclose(fp);
            set_err(err, err_len, "%s:%d: %s", path, line_no, cfg->parse_error);
            return -1;
        }
        stack_set(stack, level, key);
    }
    fclose(fp);
    return 0;
}

int rpsiod_config_load(rpsiod_config *cfg, const char *server_path, const char *sites_path, char *err, size_t err_len) {
    rpsiod_config_defaults(cfg);
    if (server_path == NULL) {
        server_path = "/etc/rpsiod/server.yml";
    }
    rpsiod_safe_copy(cfg->server_file, sizeof(cfg->server_file), server_path);
    if (parse_server_file(cfg, server_path, err, err_len) < 0) {
        return -1;
    }
    const char *effective_sites = sites_path != NULL ? sites_path : cfg->sites_file;
    rpsiod_safe_copy(cfg->loaded_sites_file, sizeof(cfg->loaded_sites_file), effective_sites);
    if (parse_sites_file(cfg, effective_sites, err, err_len) < 0) {
        return -1;
    }
    return rpsiod_config_validate(cfg, err, err_len);
}

static bool is_absolute(const char *path) {
    return path != NULL && path[0] == '/';
}

static bool is_allowed_runtime_path(const char *path) {
    return rpsiod_starts_with(path, "/var/log/rpsiod/") ||
           rpsiod_starts_with(path, "/var/cache/rpsiod/") ||
           rpsiod_starts_with(path, "/var/lib/rpsiod/ssl/") ||
           rpsiod_starts_with(path, "/run/rpsiod/");
}

static bool value_is_one_of_ci(const char *value, const char *a, const char *b, const char *c, const char *d) {
    return (a != NULL && rpsiod_streq_ci(value, a)) ||
           (b != NULL && rpsiod_streq_ci(value, b)) ||
           (c != NULL && rpsiod_streq_ci(value, c)) ||
           (d != NULL && rpsiod_streq_ci(value, d));
}

static void normalize_route_host(const char *host, char *out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    size_t i = 0;
    for (; host != NULL && host[i] != '\0' && i + 1 < out_len; i++) {
        out[i] = (char)tolower((unsigned char)host[i]);
    }
    out[i] = '\0';
}

static unsigned long route_hash_key(const char *host, uint16_t port, const char *listen_ip, bool default_site) {
    unsigned long h = 1469598103934665603ULL;
    const unsigned char *p = (const unsigned char *)(default_site ? "*" : host);
    while (*p != '\0') {
        h ^= (unsigned long)tolower(*p++);
        h *= 1099511628211ULL;
    }
    h ^= (unsigned long)port;
    h *= 1099511628211ULL;
    p = (const unsigned char *)listen_ip;
    while (p != NULL && *p != '\0') {
        h ^= (unsigned long)*p++;
        h *= 1099511628211ULL;
    }
    return h;
}

static bool route_entry_matches(const rpsiod_route_entry *entry, const char *host, uint16_t port, const char *listen_ip, bool default_site) {
    return entry->used &&
           entry->default_site == default_site &&
           entry->port == port &&
           strcmp(entry->listen_ip, listen_ip) == 0 &&
           (default_site || rpsiod_streq_ci(entry->host, host));
}

static int add_route_entry(rpsiod_config *cfg, const char *host, uint16_t port, const char *listen_ip, size_t site_index, bool default_site, char *err, size_t err_len) {
    if (port == 0) {
        return 0;
    }
    char normalized_host[256];
    normalize_route_host(host, normalized_host, sizeof(normalized_host));
    const char *key_host = default_site ? "" : normalized_host;
    unsigned long start = route_hash_key(key_host, port, listen_ip, default_site) % RPSIOD_ROUTE_TABLE_SIZE;
    for (size_t probe = 0; probe < RPSIOD_ROUTE_TABLE_SIZE; probe++) {
        size_t idx = (start + probe) % RPSIOD_ROUTE_TABLE_SIZE;
        rpsiod_route_entry *entry = &cfg->route_table[idx];
        if (!entry->used) {
            entry->used = true;
            entry->default_site = default_site;
            rpsiod_safe_copy(entry->host, sizeof(entry->host), key_host);
            rpsiod_safe_copy(entry->listen_ip, sizeof(entry->listen_ip), listen_ip);
            entry->port = port;
            entry->site_index = site_index;
            cfg->route_count++;
            return 0;
        }
        if (route_entry_matches(entry, key_host, port, listen_ip, default_site)) {
            if (entry->site_index != site_index) {
                set_err(err, err_len, "duplicate route for %s%s%s on %s:%u",
                        default_site ? "default" : "'",
                        default_site ? "" : key_host,
                        default_site ? "" : "'",
                        listen_ip,
                        port);
                return -1;
            }
            return 0;
        }
    }
    set_err(err, err_len, "route table is full");
    return -1;
}

static bool explicit_default_domain(const char *domain) {
    return strcmp(domain, "*") == 0 || rpsiod_streq_ci(domain, "default");
}

static int build_route_table(rpsiod_config *cfg, char *err, size_t err_len) {
    memset(cfg->route_table, 0, sizeof(cfg->route_table));
    cfg->route_count = 0;
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        if (!site->enabled) {
            continue;
        }
        for (size_t d = 0; d < site->domain_count; d++) {
            bool is_default = explicit_default_domain(site->domains[d]);
            if (add_route_entry(cfg, site->domains[d], site->http_port, site->listen_ip, i, is_default, err, err_len) < 0 ||
                add_route_entry(cfg, site->domains[d], site->https_port, site->listen_ip, i, is_default, err, err_len) < 0) {
                return -1;
            }
            if (!is_default && site->redirect_www_enabled) {
                char redirect_host[256] = "";
                if (rpsiod_streq_ci(site->redirect_www_mode, "apexToWww") &&
                    strncmp(site->domains[d], "www.", 4) != 0 &&
                    snprintf(redirect_host, sizeof(redirect_host), "www.%s", site->domains[d]) < (int)sizeof(redirect_host)) {
                    if (add_route_entry(cfg, redirect_host, site->http_port, site->listen_ip, i, false, err, err_len) < 0 ||
                        add_route_entry(cfg, redirect_host, site->https_port, site->listen_ip, i, false, err, err_len) < 0) {
                        return -1;
                    }
                } else if (rpsiod_streq_ci(site->redirect_www_mode, "wwwToApex") &&
                           strncmp(site->domains[d], "www.", 4) == 0) {
                    rpsiod_safe_copy(redirect_host, sizeof(redirect_host), site->domains[d] + 4);
                    if (add_route_entry(cfg, redirect_host, site->http_port, site->listen_ip, i, false, err, err_len) < 0 ||
                        add_route_entry(cfg, redirect_host, site->https_port, site->listen_ip, i, false, err, err_len) < 0) {
                        return -1;
                    }
                }
            }
        }
    }
    return 0;
}

int rpsiod_config_validate(rpsiod_config *cfg, char *err, size_t err_len) {
    if (!value_is_one_of_ci(cfg->logging_level, "debug", "info", "warn", "error")) {
        set_err(err, err_len, "logging.level must be debug, info, warn, or error");
        return -1;
    }
    if (!value_is_one_of_ci(cfg->logging_format, "text", NULL, NULL, NULL)) {
        set_err(err, err_len, "logging.format must be text");
        return -1;
    }
    if (cfg->benchmarks_port == 0) {
        set_err(err, err_len, "benchmarks.listen.port must be between 1 and 65535");
        return -1;
    }
    if (!is_absolute(cfg->sites_file)) {
        set_err(err, err_len, "server.config.sitesFile must be absolute");
        return -1;
    }
    if (strcmp(cfg->sites_file, "/etc/rpsiod/sites.yml") != 0 && strstr(cfg->sites_file, "/etc/rpsiod/") != cfg->sites_file) {
        set_err(err, err_len, "configuration must live under /etc/rpsiod");
        return -1;
    }
    if (!is_absolute(cfg->pid_file) || !is_allowed_runtime_path(cfg->pid_file)) {
        set_err(err, err_len, "linux.pidFile must be an allowed runtime path");
        return -1;
    }
    if (cfg->access_log.enabled && (!is_absolute(cfg->access_log.path) || !rpsiod_starts_with(cfg->access_log.path, "/var/log/rpsiod/"))) {
        set_err(err, err_len, "global access log must be under /var/log/rpsiod");
        return -1;
    }
    if (cfg->error_log.enabled && (!is_absolute(cfg->error_log.path) || !rpsiod_starts_with(cfg->error_log.path, "/var/log/rpsiod/"))) {
        set_err(err, err_len, "global error log must be under /var/log/rpsiod");
        return -1;
    }
    if (!rpsiod_streq_ci(cfg->benchmarks_ip, "127.0.0.1")) {
        set_err(err, err_len, "benchmark HTTP API must default to 127.0.0.1");
        return -1;
    }
    if (cfg->site_count == 0) {
        set_err(err, err_len, "sites.yml must define at least one site");
        return -1;
    }
    if (cfg->open_file_cache_max > RPSIOD_OPEN_FILE_CACHE_MAX) {
        cfg->open_file_cache_max = RPSIOD_OPEN_FILE_CACHE_MAX;
    }
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        if (site->name[0] == '\0') {
            snprintf(site->name, sizeof(site->name), "site-%zu", i + 1);
        }
        if (site->domain_count == 0) {
            set_err(err, err_len, "site '%s' must define match.domains", site->name);
            return -1;
        }
        if (!value_is_one_of_ci(site->serve_as, "http", "https", NULL, NULL)) {
            set_err(err, err_len, "site '%s': serveAs must be http or https", site->name);
            return -1;
        }
        for (size_t d = 0; d < site->domain_count; d++) {
            if (site->domains[d][0] == '\0') {
                set_err(err, err_len, "site '%s': match.domains entries must not be empty", site->name);
                return -1;
            }
            for (size_t e = d + 1; e < site->domain_count; e++) {
                if (rpsiod_streq_ci(site->domains[d], site->domains[e])) {
                    set_err(err, err_len, "site '%s': duplicate domain '%s'", site->name, site->domains[d]);
                    return -1;
                }
            }
        }
        if (site->http_port == 0 || site->https_port == 0 || site->php_port == 0 || site->proxy_port == 0) {
            set_err(err, err_len, "site '%s': configured ports must be between 1 and 65535", site->name);
            return -1;
        }
        bool is_static = rpsiod_streq_ci(site->routing_type, "static");
        bool is_proxy = rpsiod_streq_ci(site->routing_type, "proxy");
        bool is_php = rpsiod_streq_ci(site->routing_type, "php");
        if (!is_static && !is_proxy && !is_php) {
            set_err(err, err_len, "site '%s': routing.type must be static, proxy, or php", site->name);
            return -1;
        }
        if (!value_is_one_of_ci(site->redirect_www_mode, "apexToWww", "wwwToApex", NULL, NULL)) {
            set_err(err, err_len, "site '%s': redirects.www.mode must be apexToWww or wwwToApex", site->name);
            return -1;
        }
        if (site->redirect_www_status != 301 && site->redirect_www_status != 302 && site->redirect_www_status != 307 && site->redirect_www_status != 308) {
            set_err(err, err_len, "site '%s': redirects.www.status must be 301, 302, 307, or 308", site->name);
            return -1;
        }
        if (is_static || is_php) {
            if (!is_absolute(site->static_root)) {
                set_err(err, err_len, "site '%s': static.root must be absolute", site->name);
                return -1;
            }
            if (realpath(site->static_root, site->static_root_real) == NULL) {
                set_err(err, err_len, "site '%s': static.root realpath failed for %s: %s", site->name, site->static_root, strerror(errno));
                return -1;
            }
            site->static_root_fd = open(site->static_root_real, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (site->static_root_fd < 0) {
                set_err(err, err_len, "site '%s': failed to open static.root %s: %s", site->name, site->static_root_real, strerror(errno));
                return -1;
            }
            if (is_php) {
                site->php_enabled = true;
            }
        } else {
            if (!rpsiod_streq_ci(site->proxy_scheme, "http")) {
                set_err(err, err_len, "site '%s': Phase 2 proxy supports HTTP upstreams only", site->name);
                return -1;
            }
            if (strlen(site->proxy_host) == 0 || site->proxy_port == 0) {
                set_err(err, err_len, "site '%s': proxy.upstream.host and port are required", site->name);
                return -1;
            }
        }
        if (site->index_count == 0) {
            rpsiod_safe_copy(site->indexes[site->index_count++], 128, "index.html");
        }
        if (site->allowed_method_count == 0) {
            rpsiod_safe_copy(site->allowed_methods[site->allowed_method_count++], 16, "GET");
            rpsiod_safe_copy(site->allowed_methods[site->allowed_method_count++], 16, "HEAD");
        }
        if (site->access_log.enabled && (!is_absolute(site->access_log.path) || !rpsiod_starts_with(site->access_log.path, "/var/log/rpsiod/"))) {
            set_err(err, err_len, "site '%s': access log must be under /var/log/rpsiod", site->name);
            return -1;
        }
        if (site->error_log.enabled && (!is_absolute(site->error_log.path) || !rpsiod_starts_with(site->error_log.path, "/var/log/rpsiod/"))) {
            set_err(err, err_len, "site '%s': error log must be under /var/log/rpsiod", site->name);
            return -1;
        }
        if (site->ssl_enabled) {
            if (!value_is_one_of_ci(site->ssl_mode, "auto", "manual", NULL, NULL)) {
                set_err(err, err_len, "site '%s': ssl.mode must be auto or manual", site->name);
                return -1;
            }
            if (!value_is_one_of_ci(site->ssl_provider, "letsEncrypt", "local", NULL, NULL)) {
                set_err(err, err_len, "site '%s': ssl.provider must be letsEncrypt or local", site->name);
                return -1;
            }
            if (!value_is_one_of_ci(site->ssl_challenge, "http", "dns", NULL, NULL)) {
                set_err(err, err_len, "site '%s': ssl.challenge must be http or dns", site->name);
                return -1;
            }
            if (site->ssl_storage[0] == '\0') {
                snprintf(site->ssl_storage, sizeof(site->ssl_storage), "/var/lib/rpsiod/ssl/%s", site->domains[0]);
            }
            if (!is_absolute(site->ssl_storage) || !rpsiod_starts_with(site->ssl_storage, "/var/lib/rpsiod/ssl/")) {
                set_err(err, err_len, "site '%s': ssl.storage must be under /var/lib/rpsiod/ssl", site->name);
                return -1;
            }
        }
        if (site->php_enabled) {
            if (!rpsiod_streq_ci(site->php_handler_type, "socket") && !rpsiod_streq_ci(site->php_handler_type, "tcp")) {
                set_err(err, err_len, "site '%s': php.handler.type must be socket or tcp", site->name);
                return -1;
            }
            if (rpsiod_streq_ci(site->php_handler_type, "socket") && !is_absolute(site->php_socket)) {
                set_err(err, err_len, "site '%s': php.handler.socket must be absolute", site->name);
                return -1;
            }
        }
    }
    return build_route_table(cfg, err, err_len);
}

static rpsiod_site_config *lookup_route(rpsiod_config *cfg, const char *host, uint16_t port, const char *listen_ip, bool default_site) {
    char normalized_host[256];
    normalize_route_host(host, normalized_host, sizeof(normalized_host));
    const char *key_host = default_site ? "" : normalized_host;
    unsigned long start = route_hash_key(key_host, port, listen_ip, default_site) % RPSIOD_ROUTE_TABLE_SIZE;
    for (size_t probe = 0; probe < RPSIOD_ROUTE_TABLE_SIZE; probe++) {
        size_t idx = (start + probe) % RPSIOD_ROUTE_TABLE_SIZE;
        rpsiod_route_entry *entry = &cfg->route_table[idx];
        if (!entry->used) {
            return NULL;
        }
        if (route_entry_matches(entry, key_host, port, listen_ip, default_site)) {
            return entry->site_index < cfg->site_count ? &cfg->sites[entry->site_index] : NULL;
        }
    }
    return NULL;
}

rpsiod_site_config *rpsiod_config_find_site_for_listener(rpsiod_config *cfg, const char *host, uint16_t port, const char *listen_ip) {
    const char *specific_ip = listen_ip != NULL && listen_ip[0] != '\0' ? listen_ip : "0.0.0.0";
    rpsiod_site_config *site = lookup_route(cfg, host, port, specific_ip, false);
    if (site == NULL && strcmp(specific_ip, "0.0.0.0") != 0) {
        site = lookup_route(cfg, host, port, "0.0.0.0", false);
    }
    if (site != NULL) {
        return site;
    }
    site = lookup_route(cfg, "", port, specific_ip, true);
    if (site == NULL && strcmp(specific_ip, "0.0.0.0") != 0) {
        site = lookup_route(cfg, "", port, "0.0.0.0", true);
    }
    return site;
}

rpsiod_site_config *rpsiod_config_find_site(rpsiod_config *cfg, const char *host, uint16_t port) {
    return rpsiod_config_find_site_for_listener(cfg, host, port, NULL);
}

void rpsiod_config_close_site_caches(rpsiod_config *cfg) {
    if (cfg == NULL) {
        return;
    }
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        for (size_t j = 0; j < RPSIOD_OPEN_FILE_CACHE_MAX; j++) {
            if (site->open_file_cache[j].fd >= 0) {
                close(site->open_file_cache[j].fd);
                site->open_file_cache[j].fd = -1;
            }
            site->open_file_cache[j].valid = false;
        }
        site->open_file_cache_count = 0;
    }
}

bool rpsiod_site_allows_method(const rpsiod_site_config *site, const char *method) {
    if (rpsiod_streq_ci(method, "HEAD") && rpsiod_site_allows_method(site, "GET")) {
        return true;
    }
    for (size_t i = 0; i < site->allowed_method_count; i++) {
        if (rpsiod_streq_ci(site->allowed_methods[i], method)) {
            return true;
        }
    }
    return false;
}

const char *rpsiod_site_error_page(const rpsiod_site_config *site, int status) {
    for (size_t i = 0; i < site->error_page_count; i++) {
        if (site->error_pages[i].code == status) {
            return site->error_pages[i].path;
        }
    }
    return NULL;
}
