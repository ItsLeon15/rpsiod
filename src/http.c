#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "http.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>

static bool valid_header_block_newlines(const char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\r') {
            if (i + 1 >= len || buf[i + 1] != '\n') {
                return false;
            }
            i++;
        } else if (buf[i] == '\n') {
            return false;
        }
    }
    return true;
}

static bool valid_token_char(unsigned char ch) {
    return (ch >= '0' && ch <= '9') ||
           (ch >= 'A' && ch <= 'Z') ||
           (ch >= 'a' && ch <= 'z') ||
           ch == '!' || ch == '#' || ch == '$' || ch == '%' ||
           ch == '&' || ch == '\'' || ch == '*' || ch == '+' ||
           ch == '-' || ch == '.' || ch == '^' || ch == '_' ||
           ch == '`' || ch == '|' || ch == '~';
}

static bool valid_header_name(const char *name, size_t len) {
    if (len == 0) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (!valid_token_char((unsigned char)name[i])) {
            return false;
        }
    }
    return true;
}

static bool valid_header_value(const char *value, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)value[i];
        if ((ch < 0x20 && ch != '\t') || ch == 0x7f) {
            return false;
        }
    }
    return true;
}

static bool copy_trimmed_value(char *out, size_t out_len, const char *value, size_t len) {
    while (len > 0 && (*value == ' ' || *value == '\t')) {
        value++;
        len--;
    }
    while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t')) {
        len--;
    }
    if (len >= out_len) {
        return false;
    }
    memcpy(out, value, len);
    out[len] = '\0';
    return true;
}

static bool parse_host_value(const char *value, size_t len, char *out, size_t out_len) {
    char host[RPSIOD_HOST_LEN];
    if (!copy_trimmed_value(host, sizeof(host), value, len)) {
        return false;
    }
    size_t initial_host_len = strlen(host);
    if (initial_host_len == 0) {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *)host; *p != '\0'; p++) {
        if (*p <= 0x20 || *p >= 0x7f || *p == '/' || *p == '\\') {
            return false;
        }
    }
    if (host[0] == '[') {
        char *end = strchr(host, ']');
        if (end == NULL || end == host + 1) {
            return false;
        }
        if (end[1] == ':') {
            const char *port_text = end + 2;
            if (*port_text == '\0') {
                return false;
            }
            unsigned long port = 0;
            for (const char *port_char = port_text; *port_char != '\0'; port_char++) {
                if (*port_char < '0' || *port_char > '9') {
                    return false;
                }
                port = port * 10 + (unsigned long)(*port_char - '0');
                if (port > 65535UL) {
                    return false;
                }
            }
        } else if (end[1] != '\0') {
            return false;
        }
        end[1] = '\0';
    } else {
        char *colon = strrchr(host, ':');
        if (colon != NULL && strchr(host, ':') == colon) {
            const char *port_text = colon + 1;
            if (*port_text == '\0') {
                return false;
            }
            unsigned long port = 0;
            for (const char *port_char = port_text; *port_char != '\0'; port_char++) {
                if (*port_char < '0' || *port_char > '9') {
                    return false;
                }
                port = port * 10 + (unsigned long)(*port_char - '0');
                if (port > 65535UL) {
                    return false;
                }
            }
            *colon = '\0';
        }
    }
    size_t host_len = strlen(host);
    if (host_len == 0 || host_len >= out_len) {
        return false;
    }
    memcpy(out, host, host_len + 1);
    return true;
}

static bool parse_content_length(const char *value, unsigned long long *out) {
    if (value[0] == '\0') {
        return false;
    }
    for (const char *digit = value; *digit != '\0'; digit++) {
        if (*digit < '0' || *digit > '9') {
            return false;
        }
    }
    errno = 0;
    char *num_end = NULL;
    unsigned long long n = strtoull(value, &num_end, 10);
    if (errno == ERANGE || num_end == value) {
        return false;
    }
    while (*num_end == ' ' || *num_end == '\t') {
        num_end++;
    }
    if (*num_end != '\0') {
        return false;
    }
    *out = n;
    return true;
}

static bool valid_method(const char *method, size_t len) {
    if (len == 0 || len >= RPSIOD_METHOD_LEN) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (!valid_token_char((unsigned char)method[i])) {
            return false;
        }
    }
    return true;
}

static bool valid_request_target_bytes(const char *target, size_t len) {
    if (len == 0 || len >= RPSIOD_PATH_LEN) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)target[i];
        if (ch <= 0x20 || ch == 0x7f) {
            return false;
        }
    }
    return true;
}

static bool authority_matches_host(const char *authority, const char *host) {
    char parsed_authority[RPSIOD_HOST_LEN];
    char host_line[RPSIOD_HOST_LEN];
    size_t authority_len = strlen(authority);
    size_t host_len = strlen(host);
    return parse_host_value(authority, authority_len, parsed_authority, sizeof(parsed_authority)) &&
           parse_host_value(host, host_len, host_line, sizeof(host_line)) &&
           rpsiod_streq_ci(parsed_authority, host_line);
}

static bool parse_request_target(const char *target, size_t target_len,
                                 char *path, size_t path_len,
                                 char *absolute_authority, size_t authority_len,
                                 bool *absolute_form) {
    *absolute_form = false;
    absolute_authority[0] = '\0';
    if (!valid_request_target_bytes(target, target_len)) {
        return false;
    }
    const char *origin = target;
    size_t origin_len = target_len;
    if ((target_len >= 7 && strncasecmp(target, "http://", 7) == 0) ||
        (target_len >= 8 && strncasecmp(target, "https://", 8) == 0)) {
        size_t scheme_len = target[4] == ':' ? 7 : 8;
        const char *authority = target + scheme_len;
        const char *slash = memchr(authority, '/', target_len - scheme_len);
        size_t auth_len = slash != NULL ? (size_t)(slash - authority) : target_len - scheme_len;
        if (auth_len == 0 || auth_len >= authority_len) {
            return false;
        }
        memcpy(absolute_authority, authority, auth_len);
        absolute_authority[auth_len] = '\0';
        if (slash == NULL) {
            origin = "/";
            origin_len = 1;
        } else {
            origin = slash;
            origin_len = target_len - (size_t)(slash - target);
        }
        *absolute_form = true;
    }
    if (origin_len == 0 || origin[0] != '/' || origin_len >= path_len) {
        return false;
    }
    memcpy(path, origin, origin_len);
    path[origin_len] = '\0';
    return true;
}

static bool parse_request_line(const char *line, size_t len, rpsiod_http_request *req,
                               char *version, size_t version_len,
                               char *absolute_authority, size_t authority_len) {
    if (len == 0) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)line[i];
        if (ch < 0x20 || ch == 0x7f) {
            return false;
        }
    }
    const char *first_space = memchr(line, ' ', len);
    if (first_space == NULL) {
        return false;
    }
    const char *target_start = first_space + 1;
    size_t method_len = (size_t)(first_space - line);
    size_t remaining = len - method_len - 1;
    const char *second_space = memchr(target_start, ' ', remaining);
    if (second_space == NULL) {
        return false;
    }
    size_t target_len = (size_t)(second_space - target_start);
    const char *version_start = second_space + 1;
    size_t parsed_version_len = len - (size_t)(version_start - line);
    if (memchr(version_start, ' ', parsed_version_len) != NULL ||
        parsed_version_len == 0 || parsed_version_len >= version_len ||
        !valid_method(line, method_len)) {
        return false;
    }
    memcpy(req->method, line, method_len);
    req->method[method_len] = '\0';
    memcpy(version, version_start, parsed_version_len);
    version[parsed_version_len] = '\0';
    if (!rpsiod_streq_ci(version, "HTTP/1.0") && !rpsiod_streq_ci(version, "HTTP/1.1")) {
        return false;
    }
    return parse_request_target(target_start, target_len, req->path, sizeof(req->path),
                                absolute_authority, authority_len, &req->absolute_form);
}

static bool header_token_present(const char *value, const char *needle) {
    const char *cursor = value;
    size_t needle_len = strlen(needle);
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == ',') {
            cursor++;
        }
        const char *start = cursor;
        while (*cursor != '\0' && *cursor != ',') {
            cursor++;
        }
        const char *end = cursor;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        if ((size_t)(end - start) == needle_len && strncasecmp(start, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool parse_byte_range(const char *value, rpsiod_http_request *req) {
    if (!rpsiod_starts_with(value, "bytes=")) {
        return false;
    }
    const char *spec = value + 6;
    if (strchr(spec, ',') != NULL) {
        return false;
    }
    const char *dash = strchr(spec, '-');
    if (dash == NULL) {
        return false;
    }
    req->range_present = true;
    if (dash == spec) {
        char *end = NULL;
        unsigned long long suffix = strtoull(dash + 1, &end, 10);
        if (end == dash + 1 || *end != '\0' || suffix == 0) {
            return false;
        }
        req->range_suffix = true;
        req->range_start = suffix;
        return true;
    }
    char *end = NULL;
    unsigned long long start = strtoull(spec, &end, 10);
    if (end != dash) {
        return false;
    }
    req->range_start = start;
    if (dash[1] != '\0') {
        unsigned long long range_end = strtoull(dash + 1, &end, 10);
        if (end == dash + 1 || *end != '\0' || range_end < start) {
            return false;
        }
        req->range_end = range_end;
        req->range_has_end = true;
    }
    return true;
}

int rpsiod_http_parse_request(const char *buf, size_t len, rpsiod_http_request *req) {
    memset(req, 0, sizeof(*req));
    req->keep_alive = false;
    bool connection_upgrade = false;
    bool upgrade_websocket = false;
    bool have_content_length = false;
    unsigned long long seen_content_length = 0;
    bool have_transfer_encoding = false;
    bool have_host = false;
    unsigned header_count = 0;

    const char *end = memmem(buf, len, "\r\n\r\n", 4);
    if (end == NULL) {
        return 0;
    }
    req->header_len = (size_t)(end - buf) + 4;
    if (req->header_len > 16384 || !valid_header_block_newlines(buf, req->header_len)) {
        return -1;
    }

    const char *line_end = memmem(buf, len, "\r\n", 2);
    if (line_end == NULL) {
        return -1;
    }
    size_t first_len = (size_t)(line_end - buf);
    if (first_len > 2048) {
        return -1;
    }
    char version[32];
    char absolute_authority[RPSIOD_HOST_LEN];
    if (!parse_request_line(buf, first_len, req, version, sizeof(version), absolute_authority, sizeof(absolute_authority))) {
        return -1;
    }
    char *query = strchr(req->path, '?');
    if (query != NULL) {
        rpsiod_safe_copy(req->query_string, sizeof(req->query_string), query + 1);
    }
    req->head_only = rpsiod_streq_ci(req->method, "HEAD");
    req->keep_alive = rpsiod_streq_ci(version, "HTTP/1.1");

    const char *p = line_end + 2;
    while (p < end) {
        const char *next = memmem(p, (size_t)(end - p), "\r\n", 2);
        if (next == NULL) {
            next = end;
        }
        size_t line_len = (size_t)(next - p);
        if (line_len >= 1024) {
            return -1;
        }
        if (line_len > 0) {
            header_count++;
            if (header_count > 100) {
                return -1;
            }
            const char *colon = memchr(p, ':', line_len);
            if (colon == NULL) {
                return -1;
            }
            size_t name_len = (size_t)(colon - p);
            if (!valid_header_name(p, name_len)) {
                return -1;
            }
            const char *raw_value = colon + 1;
            size_t raw_value_len = line_len - name_len - 1;
            if (!valid_header_value(raw_value, raw_value_len)) {
                return -1;
            }
            char name[128];
            char value[1024];
            if (name_len >= sizeof(name) || !copy_trimmed_value(value, sizeof(value), raw_value, raw_value_len)) {
                return -1;
            }
            memcpy(name, p, name_len);
            name[name_len] = '\0';
            if (rpsiod_streq_ci(name, "Host")) {
                if (have_host || !parse_host_value(value, strlen(value), req->host, sizeof(req->host))) {
                    return -1;
                }
                have_host = true;
            } else if (rpsiod_streq_ci(name, "Accept-Encoding")) {
                rpsiod_safe_copy(req->accept_encoding, sizeof(req->accept_encoding), value);
            } else if (rpsiod_streq_ci(name, "If-None-Match")) {
                rpsiod_safe_copy(req->if_none_match, sizeof(req->if_none_match), value);
            } else if (rpsiod_streq_ci(name, "If-Modified-Since")) {
                rpsiod_safe_copy(req->if_modified_since, sizeof(req->if_modified_since), value);
            } else if (rpsiod_streq_ci(name, "Range")) {
                if (!parse_byte_range(value, req)) {
                    return -1;
                }
            } else if (rpsiod_streq_ci(name, "Content-Length")) {
                unsigned long long n = 0;
                if (!parse_content_length(value, &n)) {
                    return -1;
                }
                if (have_content_length && n != seen_content_length) {
                    return -1;
                }
                have_content_length = true;
                seen_content_length = n;
                req->content_length = n;
            } else if (rpsiod_streq_ci(name, "Transfer-Encoding")) {
                have_transfer_encoding = true;
                if (!rpsiod_streq_ci(value, "chunked")) {
                    return -1;
                }
            } else if (rpsiod_streq_ci(name, "Connection")) {
                if (header_token_present(value, "close")) {
                    req->keep_alive = false;
                } else if (header_token_present(value, "keep-alive")) {
                    req->keep_alive = true;
                }
                if (header_token_present(value, "upgrade")) {
                    connection_upgrade = true;
                }
            } else if (rpsiod_streq_ci(name, "Upgrade")) {
                if (rpsiod_streq_ci(value, "websocket")) {
                    upgrade_websocket = true;
                }
            } else if (rpsiod_streq_ci(name, "X-Rpsiod-Internal-Scheme")) {
                if (rpsiod_streq_ci(value, "https")) {
                    req->internal_https = true;
                }
            } else if (rpsiod_streq_ci(name, "X-Rpsiod-Trace")) {
                req->trace_request = rpsiod_streq_ci(value, "1") || rpsiod_streq_ci(value, "true");
            }
        }
        p = next == end ? end : next + 2;
    }
    if (have_content_length && have_transfer_encoding) {
        return -1;
    }
    if (have_transfer_encoding) {
        return -1;
    }
    if (!have_host) {
        return -1;
    }
    if (req->absolute_form && !authority_matches_host(absolute_authority, req->host)) {
        return -1;
    }
    req->upgrade_websocket = connection_upgrade && upgrade_websocket;
    return 1;
}

const char *rpsiod_http_status_text(int status) {
    switch (status) {
        case 200: return "OK";
        case 206: return "Partial Content";
        case 304: return "Not Modified";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 416: return "Range Not Satisfiable";
        case 429: return "Too Many Requests";
        case 502: return "Bad Gateway";
        case 504: return "Gateway Timeout";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default: return "Error";
    }
}
