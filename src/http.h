#ifndef RPSIOD_HTTP_H
#define RPSIOD_HTTP_H

#include <stdbool.h>
#include <stddef.h>

#define RPSIOD_METHOD_LEN 16
#define RPSIOD_PATH_LEN 2048
#define RPSIOD_HOST_LEN 256
#define RPSIOD_ENCODING_LEN 256
#define RPSIOD_VALIDATOR_LEN 256

typedef struct {
    char method[RPSIOD_METHOD_LEN];
    char path[RPSIOD_PATH_LEN];
    char host[RPSIOD_HOST_LEN];
    char accept_encoding[RPSIOD_ENCODING_LEN];
    char if_none_match[RPSIOD_VALIDATOR_LEN];
    char if_modified_since[RPSIOD_VALIDATOR_LEN];
    char query_string[RPSIOD_PATH_LEN];
    size_t header_len;
    unsigned long long content_length;
    unsigned long long range_start;
    unsigned long long range_end;
    bool keep_alive;
    bool head_only;
    bool upgrade_websocket;
    bool internal_https;
    bool range_present;
    bool range_suffix;
    bool range_has_end;
    bool trace_request;
    bool absolute_form;
} rpsiod_http_request;

int rpsiod_http_parse_request(const char *buf, size_t len, rpsiod_http_request *req);
const char *rpsiod_http_status_text(int status);

#endif
