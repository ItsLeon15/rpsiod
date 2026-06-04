#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "http2.h"
#include "http.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <nghttp2/nghttp2.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define H2_MAX_HEADER_VALUE 4096
#define H2_MAX_RESPONSE (64U * 1024U * 1024U)
#define H2_IDLE_TIMEOUT_MS 2000
#define H2_BACKEND_RETRY_MS 50.0
#define H2_BACKEND_MAX_ATTEMPTS 8

typedef struct h2_response_header {
    char name[128];
    char value[H2_MAX_HEADER_VALUE];
} h2_response_header;

typedef struct h2_response {
    int status;
    h2_response_header headers[96];
    size_t header_count;
    unsigned char *body;
    size_t body_len;
} h2_response;

typedef enum {
    H2_BACKEND_NONE = 0,
    H2_BACKEND_CONNECTING,
    H2_BACKEND_WRITING,
    H2_BACKEND_READING,
    H2_BACKEND_DONE,
    H2_BACKEND_FAILED
} h2_backend_state;

typedef struct h2_stream {
    int32_t id;
    char method[16];
    char path[2048];
    char authority[256];
    bool request_seen;
    unsigned char *response_body;
    size_t response_body_len;
    size_t response_body_off;
    int backend_fd;
    h2_backend_state backend_state;
    char backend_request[8192];
    size_t backend_request_len;
    size_t backend_request_off;
    unsigned char *raw_response;
    size_t raw_response_len;
    size_t raw_response_cap;
    int backend_attempts;
    bool response_submitted;
    bool first_data_sent;
    struct timespec stream_started;
    struct timespec backend_started;
    struct timespec headers_submitted;
    struct timespec first_data_sent_at;
    struct timespec last_data_sent_at;
    struct h2_stream *next;
} h2_stream;

typedef struct h2_conn {
    SSL *ssl;
    rpsiod_config *cfg;
    rpsiod_logger *logger;
    char client_ip[INET6_ADDRSTRLEN];
    char server_ip[INET6_ADDRSTRLEN];
    uint16_t local_port;
    h2_stream *streams;
    unsigned int active_backend_streams;
    unsigned int max_concurrent_streams_seen;
    unsigned long long tls_write_count;
    unsigned long long tls_write_bytes;
    unsigned long long data_frame_count;
    unsigned long long data_bytes;
    unsigned long long connection_window_stalls;
    unsigned long long stream_window_stalls;
} h2_conn;

static h2_stream *find_stream(h2_conn *conn, int32_t stream_id) {
    for (h2_stream *s = conn->streams; s != NULL; s = s->next) {
        if (s->id == stream_id) {
            return s;
        }
    }
    return NULL;
}

static h2_stream *get_or_create_stream(h2_conn *conn, int32_t stream_id) {
    h2_stream *s = find_stream(conn, stream_id);
    if (s != NULL) {
        return s;
    }
    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->id = stream_id;
    s->backend_fd = -1;
    (void)clock_gettime(CLOCK_MONOTONIC, &s->stream_started);
    rpsiod_safe_copy(s->method, sizeof(s->method), "GET");
    rpsiod_safe_copy(s->path, sizeof(s->path), "/");
    s->next = conn->streams;
    conn->streams = s;
    unsigned int count = 0;
    for (h2_stream *cur = conn->streams; cur != NULL; cur = cur->next) {
        count++;
    }
    if (count > conn->max_concurrent_streams_seen) {
        conn->max_concurrent_streams_seen = count;
    }
    return s;
}

static void remove_stream(h2_conn *conn, int32_t stream_id) {
    h2_stream **pp = &conn->streams;
    while (*pp != NULL) {
        h2_stream *s = *pp;
        if (s->id == stream_id) {
            *pp = s->next;
            if (s->backend_fd >= 0) {
                close(s->backend_fd);
                if (conn->active_backend_streams > 0) {
                    conn->active_backend_streams--;
                }
            }
            free(s->raw_response);
            free(s->response_body);
            free(s);
            return;
        }
        pp = &s->next;
    }
}

static double h2_elapsed_ms(const struct timespec *start, const struct timespec *end) {
    if (start->tv_sec == 0 || end->tv_sec == 0) {
        return 0.0;
    }
    return (double)(end->tv_sec - start->tv_sec) * 1000.0 +
           (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
}

static bool h2_diag_enabled(void) {
    static int enabled = -1;
    if (enabled < 0) {
        const char *env = getenv("RPSIOD_H2_DIAG");
        enabled = env != NULL && env[0] != '\0' && strcmp(env, "0") != 0;
    }
    return enabled != 0;
}

static void h2_log_stream_diag(h2_conn *conn, h2_stream *stream, const char *stage, const char *detail) {
    if (!h2_diag_enabled()) {
        return;
    }
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    rpsiod_log_error(conn->logger, NULL,
                     "h2 stream=%d stage=%s method=%s path=%s elapsed_ms=%.3f backend_ms=%.3f headers_ms=%.3f first_data_ms=%.3f last_data_ms=%.3f tls_writes=%llu tls_bytes=%llu data_frames=%llu data_bytes=%llu conn_window_stalls=%llu stream_window_stalls=%llu %s",
                     stream->id,
                     stage,
                     stream->method,
                     stream->path,
                     h2_elapsed_ms(&stream->stream_started, &now),
                     h2_elapsed_ms(&stream->backend_started, &now),
                     h2_elapsed_ms(&stream->stream_started, &stream->headers_submitted),
                     h2_elapsed_ms(&stream->stream_started, &stream->first_data_sent_at),
                     h2_elapsed_ms(&stream->stream_started, &stream->last_data_sent_at),
                     conn->tls_write_count,
                     conn->tls_write_bytes,
                     conn->data_frame_count,
                     conn->data_bytes,
                     conn->connection_window_stalls,
                     conn->stream_window_stalls,
                     detail != NULL ? detail : "");
}

static ssize_t ssl_send_callback(nghttp2_session *session, const uint8_t *data, size_t length,
                                 int flags, void *user_data) {
    (void)session;
    (void)flags;
    h2_conn *conn = user_data;
    size_t written = 0;
    while (length > 0) {
        int chunk = length > INT32_MAX ? INT32_MAX : (int)length;
        int n = SSL_write(conn->ssl, data, chunk);
        if (n <= 0) {
            int err = SSL_get_error(conn->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return written > 0 ? (ssize_t)written : NGHTTP2_ERR_WOULDBLOCK;
            }
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        conn->tls_write_count++;
        conn->tls_write_bytes += (unsigned long long)n;
        data += n;
        length -= (size_t)n;
        written += (size_t)n;
    }
    return (ssize_t)written;
}

static ssize_t response_data_callback(nghttp2_session *session, int32_t stream_id,
                                      uint8_t *buf, size_t length, uint32_t *data_flags,
                                      nghttp2_data_source *source, void *user_data) {
    (void)session;
    (void)stream_id;
    h2_stream *stream = source->ptr;
    size_t left = stream->response_body_len - stream->response_body_off;
    if (left == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    size_t n = left < length ? left : length;
    memcpy(buf, stream->response_body + stream->response_body_off, n);
    stream->response_body_off += n;
    h2_conn *conn = user_data;
    if (conn != NULL) {
        conn->data_frame_count++;
        conn->data_bytes += (unsigned long long)n;
    }
    if (!stream->first_data_sent) {
        stream->first_data_sent = true;
        (void)clock_gettime(CLOCK_MONOTONIC, &stream->first_data_sent_at);
    }
    if (stream->response_body_off == stream->response_body_len) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        (void)clock_gettime(CLOCK_MONOTONIC, &stream->last_data_sent_at);
    }
    return (ssize_t)n;
}

static bool append_bytes(unsigned char **buf, size_t *len, size_t *cap, const unsigned char *data, size_t data_len) {
    if (data_len > H2_MAX_RESPONSE || *len > H2_MAX_RESPONSE - data_len) {
        return false;
    }
    if (*len + data_len > *cap) {
        size_t next = *cap == 0 ? 8192 : *cap;
        while (next < *len + data_len) {
            if (next > H2_MAX_RESPONSE / 2) {
                next = H2_MAX_RESPONSE;
                break;
            }
            next *= 2;
        }
        unsigned char *tmp = realloc(*buf, next);
        if (tmp == NULL) {
            return false;
        }
        *buf = tmp;
        *cap = next;
    }
    memcpy(*buf + *len, data, data_len);
    *len += data_len;
    return true;
}

static bool blocked_h2_header(const char *name) {
    return rpsiod_streq_ci(name, "connection") ||
           rpsiod_streq_ci(name, "transfer-encoding") ||
           rpsiod_streq_ci(name, "upgrade") ||
           rpsiod_streq_ci(name, "keep-alive") ||
           rpsiod_streq_ci(name, "proxy-connection");
}

static bool response_has_header(const h2_response *resp, const char *name) {
    for (size_t i = 0; i < resp->header_count; i++) {
        if (rpsiod_streq_ci(resp->headers[i].name, name)) {
            return true;
        }
    }
    return false;
}

static bool header_value_has_token(const char *value, const char *token) {
    size_t token_len = strlen(token);
    const char *p = value;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        const char *start = p;
        while (*p != '\0' && *p != ',' && *p != ';') {
            p++;
        }
        const char *end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        if ((size_t)(end - start) == token_len && strncasecmp(start, token, token_len) == 0) {
            return true;
        }
        while (*p != '\0' && *p != ',') {
            p++;
        }
    }
    return false;
}

static int decode_chunked_body(const unsigned char *body, size_t body_len, unsigned char **out, size_t *out_len) {
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    size_t decoded_cap = 0;
    size_t off = 0;

    for (;;) {
        size_t line_start = off;
        while (off + 1 < body_len && !(body[off] == '\r' && body[off + 1] == '\n')) {
            off++;
        }
        if (off + 1 >= body_len) {
            free(decoded);
            return -1;
        }
        size_t line_len = off - line_start;
        off += 2;

        size_t i = 0;
        while (i < line_len && (body[line_start + i] == ' ' || body[line_start + i] == '\t')) {
            i++;
        }
        if (i == line_len) {
            free(decoded);
            return -1;
        }

        unsigned long long chunk_len = 0;
        bool saw_digit = false;
        for (; i < line_len; i++) {
            unsigned char ch = body[line_start + i];
            unsigned digit;
            if (ch >= '0' && ch <= '9') {
                digit = (unsigned)(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                digit = 10U + (unsigned)(ch - 'a');
            } else if (ch >= 'A' && ch <= 'F') {
                digit = 10U + (unsigned)(ch - 'A');
            } else {
                break;
            }
            saw_digit = true;
            if (chunk_len > (H2_MAX_RESPONSE - digit) / 16U) {
                free(decoded);
                return -1;
            }
            chunk_len = chunk_len * 16U + digit;
        }
        while (i < line_len && (body[line_start + i] == ' ' || body[line_start + i] == '\t')) {
            i++;
        }
        if (!saw_digit || (i < line_len && body[line_start + i] != ';')) {
            free(decoded);
            return -1;
        }

        if (chunk_len == 0) {
            for (;;) {
                size_t trailer_start = off;
                while (off + 1 < body_len && !(body[off] == '\r' && body[off + 1] == '\n')) {
                    off++;
                }
                if (off + 1 >= body_len) {
                    free(decoded);
                    return -1;
                }
                size_t trailer_len = off - trailer_start;
                off += 2;
                if (trailer_len == 0) {
                    *out = decoded;
                    *out_len = decoded_len;
                    return 0;
                }
            }
        }

        if (chunk_len > body_len - off || chunk_len > H2_MAX_RESPONSE ||
            decoded_len > H2_MAX_RESPONSE - (size_t)chunk_len) {
            free(decoded);
            return -1;
        }
        if (decoded_len + (size_t)chunk_len > decoded_cap) {
            size_t next = decoded_cap == 0 ? 8192 : decoded_cap;
            while (next < decoded_len + (size_t)chunk_len) {
                if (next > H2_MAX_RESPONSE / 2) {
                    next = H2_MAX_RESPONSE;
                    break;
                }
                next *= 2;
            }
            unsigned char *tmp = realloc(decoded, next);
            if (tmp == NULL) {
                free(decoded);
                return -1;
            }
            decoded = tmp;
            decoded_cap = next;
        }
        memcpy(decoded + decoded_len, body + off, (size_t)chunk_len);
        decoded_len += (size_t)chunk_len;
        off += (size_t)chunk_len;
        if (body_len - off < 2 || body[off] != '\r' || body[off + 1] != '\n') {
            free(decoded);
            return -1;
        }
        off += 2;
    }
}

static void free_response(h2_response *resp) {
    free(resp->body);
    memset(resp, 0, sizeof(*resp));
}

static int parse_loopback_response(unsigned char *raw, size_t raw_len, h2_response *resp) {
    memset(resp, 0, sizeof(*resp));
    char *headers_end = memmem(raw, raw_len, "\r\n\r\n", 4);
    if (headers_end == NULL) {
        return -1;
    }
    size_t header_len = (size_t)(headers_end - (char *)raw);
    char *headers = malloc(header_len + 1);
    if (headers == NULL) {
        return -1;
    }
    memcpy(headers, raw, header_len);
    headers[header_len] = '\0';

    char *save = NULL;
    char *line = strtok_r(headers, "\r\n", &save);
    if (line == NULL || sscanf(line, "HTTP/%*s %d", &resp->status) != 1) {
        free(headers);
        return -1;
    }
    bool chunked_body = false;
    while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
        char *colon = strchr(line, ':');
        if (colon == NULL) {
            continue;
        }
        *colon = '\0';
        char *value = colon + 1;
        rpsiod_trim(line);
        rpsiod_trim(value);
        if (rpsiod_streq_ci(line, "Transfer-Encoding") && header_value_has_token(value, "chunked")) {
            chunked_body = true;
        }
        if (blocked_h2_header(line) || line[0] == '\0' || resp->header_count >= 96) {
            continue;
        }
        rpsiod_safe_copy(resp->headers[resp->header_count].name, sizeof(resp->headers[resp->header_count].name), line);
        rpsiod_safe_copy(resp->headers[resp->header_count].value, sizeof(resp->headers[resp->header_count].value), value);
        resp->header_count++;
    }

    unsigned char *body = (unsigned char *)headers_end + 4;
    size_t body_len = raw_len - (size_t)(body - raw);
    if (chunked_body) {
        if (decode_chunked_body(body, body_len, &resp->body, &resp->body_len) < 0) {
            free(headers);
            return -1;
        }
    } else if (body_len > 0) {
        resp->body = malloc(body_len);
        if (resp->body == NULL) {
            free(headers);
            return -1;
        }
        memcpy(resp->body, body, body_len);
        resp->body_len = body_len;
    }
    free(headers);
    return 0;
}

static void close_backend_stream(h2_conn *conn, h2_stream *stream) {
    if (stream->backend_fd >= 0) {
        close(stream->backend_fd);
        stream->backend_fd = -1;
        if (conn->active_backend_streams > 0) {
            conn->active_backend_streams--;
        }
    }
}

static void start_loopback_request_async(h2_conn *conn, h2_stream *stream) {
    char authority[256];
    rpsiod_safe_copy(authority, sizeof(authority), stream->authority[0] != '\0' ? stream->authority : "localhost");
    rpsiod_strip_port(authority);
    rpsiod_site_config *site = rpsiod_config_find_site_for_listener(conn->cfg, authority, conn->local_port, conn->server_ip);
    if (site == NULL || site->http_port == 0) {
        stream->backend_state = H2_BACKEND_FAILED;
        return;
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        stream->backend_state = H2_BACKEND_FAILED;
        return;
    }
    if (rpsiod_set_nonblocking(fd) < 0) {
        close(fd);
        stream->backend_state = H2_BACKEND_FAILED;
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(site->http_port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        close(fd);
        stream->backend_state = H2_BACKEND_FAILED;
        return;
    }

    int n = snprintf(stream->backend_request, sizeof(stream->backend_request),
                     "%s %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: close\r\n"
                     "X-Forwarded-Proto: https\r\n"
                     "X-Forwarded-For: %s\r\n"
                     "X-Rpsiod-Internal-Scheme: https\r\n"
                     "\r\n",
                     stream->method,
                     stream->path,
                     stream->authority[0] != '\0' ? stream->authority : authority,
                     conn->client_ip);
    if (n < 0 || (size_t)n >= sizeof(stream->backend_request)) {
        close(fd);
        stream->backend_state = H2_BACKEND_FAILED;
        return;
    }
    stream->backend_request_len = (size_t)n;
    stream->backend_request_off = 0;
    stream->backend_fd = fd;
    stream->backend_state = H2_BACKEND_CONNECTING;
    stream->backend_attempts++;
    conn->active_backend_streams++;
    (void)clock_gettime(CLOCK_MONOTONIC, &stream->backend_started);
    h2_log_stream_diag(conn, stream, "backend-start", "wait=file-or-php");

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        stream->backend_state = H2_BACKEND_WRITING;
    } else if (errno != EINPROGRESS) {
        close_backend_stream(conn, stream);
        stream->backend_state = H2_BACKEND_FAILED;
    }
}

static void retry_delayed_loopback(h2_conn *conn, h2_stream *stream) {
    if (stream->backend_attempts >= H2_BACKEND_MAX_ATTEMPTS || stream->raw_response_len > 0 ||
        (stream->backend_state != H2_BACKEND_CONNECTING &&
         stream->backend_state != H2_BACKEND_WRITING &&
         stream->backend_state != H2_BACKEND_READING)) {
        return;
    }
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    if (h2_elapsed_ms(&stream->backend_started, &now) < H2_BACKEND_RETRY_MS) {
        return;
    }
    h2_log_stream_diag(conn, stream, "backend-retry", "wait=loopback-reuseport");
    close_backend_stream(conn, stream);
    free(stream->raw_response);
    stream->raw_response = NULL;
    stream->raw_response_len = 0;
    stream->raw_response_cap = 0;
    stream->backend_request_len = 0;
    stream->backend_request_off = 0;
    stream->backend_state = H2_BACKEND_NONE;
    start_loopback_request_async(conn, stream);
}

static int h2_progress_backend_stream(h2_conn *conn, h2_stream *stream, short revents) {
    if (stream->backend_state == H2_BACKEND_CONNECTING) {
        if ((revents & (POLLOUT | POLLERR | POLLHUP)) == 0) {
            return 0;
        }
        int socket_error = 0;
        socklen_t socket_error_len = sizeof(socket_error);
        if (getsockopt(stream->backend_fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len) < 0 ||
            socket_error != 0) {
            close_backend_stream(conn, stream);
            stream->backend_state = H2_BACKEND_FAILED;
            return 1;
        }
        stream->backend_state = H2_BACKEND_WRITING;
    }

    if (stream->backend_state == H2_BACKEND_WRITING) {
        while (stream->backend_request_off < stream->backend_request_len) {
            ssize_t n = write(stream->backend_fd,
                              stream->backend_request + stream->backend_request_off,
                              stream->backend_request_len - stream->backend_request_off);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 0;
                }
                close_backend_stream(conn, stream);
                stream->backend_state = H2_BACKEND_FAILED;
                return 1;
            }
            if (n == 0) {
                return 0;
            }
            stream->backend_request_off += (size_t)n;
        }
        stream->backend_state = H2_BACKEND_READING;
    }

    if (stream->backend_state == H2_BACKEND_READING) {
        unsigned char tmp[8192];
        for (;;) {
            ssize_t got = read(stream->backend_fd, tmp, sizeof(tmp));
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 0;
                }
                close_backend_stream(conn, stream);
                stream->backend_state = H2_BACKEND_FAILED;
                return 1;
            }
            if (got == 0) {
                close_backend_stream(conn, stream);
                stream->backend_state = H2_BACKEND_DONE;
                h2_log_stream_diag(conn, stream, "backend-done", "wait=backend");
                return 1;
            }
            if (!append_bytes(&stream->raw_response,
                              &stream->raw_response_len,
                              &stream->raw_response_cap,
                              tmp,
                              (size_t)got)) {
                close_backend_stream(conn, stream);
                stream->backend_state = H2_BACKEND_FAILED;
                return 1;
            }
        }
    }
    return 0;
}

static int submit_simple_response(nghttp2_session *session, h2_stream *stream, int status, const char *body);

static int submit_parsed_loopback_response(nghttp2_session *session, h2_conn *conn, h2_stream *stream) {
    h2_response resp;
    if (stream->raw_response == NULL ||
        parse_loopback_response(stream->raw_response, stream->raw_response_len, &resp) < 0) {
        return submit_simple_response(session, stream, 502, "502 Bad Gateway\n");
    }

    bool add_hsts = !response_has_header(&resp, "Strict-Transport-Security");
    nghttp2_nv *headers = calloc(resp.header_count + 1 + (add_hsts ? 1U : 0U), sizeof(*headers));
    char status[4];
    if (headers == NULL) {
        free_response(&resp);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    snprintf(status, sizeof(status), "%d", resp.status);
    headers[0].name = (uint8_t *)":status";
    headers[0].namelen = 7;
    headers[0].value = (uint8_t *)status;
    headers[0].valuelen = strlen(status);

    size_t out_count = 1;
    for (size_t i = 0; i < resp.header_count; i++) {
        headers[out_count].name = (uint8_t *)resp.headers[i].name;
        headers[out_count].namelen = strlen(resp.headers[i].name);
        headers[out_count].value = (uint8_t *)resp.headers[i].value;
        headers[out_count].valuelen = strlen(resp.headers[i].value);
        headers[out_count].flags = NGHTTP2_NV_FLAG_NONE;
        out_count++;
    }
    if (add_hsts) {
        headers[out_count].name = (uint8_t *)"strict-transport-security";
        headers[out_count].namelen = 25;
        headers[out_count].value = (uint8_t *)"max-age=31536000; includeSubDomains";
        headers[out_count].valuelen = 35;
        headers[out_count].flags = NGHTTP2_NV_FLAG_NONE;
        out_count++;
    }

    stream->response_body = resp.body;
    stream->response_body_len = rpsiod_streq_ci(stream->method, "HEAD") ? 0 : resp.body_len;
    stream->response_body_off = 0;
    resp.body = NULL;
    resp.body_len = 0;

    nghttp2_data_provider provider;
    memset(&provider, 0, sizeof(provider));
    provider.source.ptr = stream;
    provider.read_callback = response_data_callback;
    int rc = nghttp2_submit_response(session, stream->id, headers, out_count, stream->response_body_len > 0 ? &provider : NULL);
    if (rc == 0) {
        (void)clock_gettime(CLOCK_MONOTONIC, &stream->headers_submitted);
        if (stream->response_body_len == 0) {
            stream->last_data_sent_at = stream->headers_submitted;
        }
        h2_log_stream_diag(conn, stream, "headers-submitted", "wait=send-queue");
    }
    free(headers);
    free_response(&resp);
    return rc;
}

static int submit_simple_response(nghttp2_session *session, h2_stream *stream, int status, const char *body) {
    char status_text[4];
    snprintf(status_text, sizeof(status_text), "%d", status);
    nghttp2_nv hdr[] = {
        {(uint8_t *)":status", (uint8_t *)status_text, 7, strlen(status_text), NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)"content-type", (uint8_t *)"text/plain; charset=utf-8", 12, 25, NGHTTP2_NV_FLAG_NONE},
    };
    size_t len = strlen(body);
    stream->response_body = malloc(len);
    if (stream->response_body == NULL) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    memcpy(stream->response_body, body, len);
    stream->response_body_len = len;
    stream->response_body_off = 0;
    nghttp2_data_provider provider;
    memset(&provider, 0, sizeof(provider));
    provider.source.ptr = stream;
    provider.read_callback = response_data_callback;
    return nghttp2_submit_response(session, stream->id, hdr, 2, &provider);
}

static int on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    (void)session;
    h2_conn *conn = user_data;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        h2_stream *stream = get_or_create_stream(conn, frame->hd.stream_id);
        if (stream == NULL) {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        stream->request_seen = true;
    }
    return 0;
}

static int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags, void *user_data) {
    (void)session;
    (void)flags;
    h2_conn *conn = user_data;
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    h2_stream *stream = get_or_create_stream(conn, frame->hd.stream_id);
    if (stream == NULL) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
        size_t n = valuelen < sizeof(stream->method) - 1 ? valuelen : sizeof(stream->method) - 1;
        memcpy(stream->method, value, n);
        stream->method[n] = '\0';
    } else if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
        size_t n = valuelen < sizeof(stream->path) - 1 ? valuelen : sizeof(stream->path) - 1;
        memcpy(stream->path, value, n);
        stream->path[n] = '\0';
    } else if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
        size_t n = valuelen < sizeof(stream->authority) - 1 ? valuelen : sizeof(stream->authority) - 1;
        memcpy(stream->authority, value, n);
        stream->authority[n] = '\0';
    }
    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    h2_conn *conn = user_data;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
        h2_stream *stream = find_stream(conn, frame->hd.stream_id);
        if (stream == NULL) {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        if (stream->authority[0] == '\0') {
            rpsiod_safe_copy(stream->authority, sizeof(stream->authority), "localhost");
        }
        if (!rpsiod_streq_ci(stream->method, "GET") && !rpsiod_streq_ci(stream->method, "HEAD")) {
            int rc = submit_simple_response(session, stream, 405, "405 Method Not Allowed\n");
            stream->response_submitted = rc == 0;
            return rc;
        }
        start_loopback_request_async(conn, stream);
        return 0;
    }
    return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
    (void)session;
    (void)error_code;
    h2_conn *conn = user_data;
    remove_stream(conn, stream_id);
    return 0;
}

static void free_all_streams(h2_conn *conn) {
    while (conn->streams != NULL) {
        remove_stream(conn, conn->streams->id);
    }
}

static bool has_active_streams(const h2_conn *conn) {
    return conn->streams != NULL;
}

static bool has_backend_work(const h2_conn *conn) {
    for (h2_stream *stream = conn->streams; stream != NULL; stream = stream->next) {
        if (stream->backend_state == H2_BACKEND_CONNECTING ||
            stream->backend_state == H2_BACKEND_WRITING ||
            stream->backend_state == H2_BACKEND_READING) {
            return true;
        }
    }
    return false;
}

static int submit_ready_streams(nghttp2_session *session, h2_conn *conn) {
    for (h2_stream *stream = conn->streams; stream != NULL; stream = stream->next) {
        if (stream->response_submitted) {
            continue;
        }
        int rc = 0;
        if (stream->backend_state == H2_BACKEND_DONE) {
            rc = submit_parsed_loopback_response(session, conn, stream);
        } else if (stream->backend_state == H2_BACKEND_FAILED) {
            rc = submit_simple_response(session, stream, 502, "502 Bad Gateway\n");
            if (rc == 0) {
                (void)clock_gettime(CLOCK_MONOTONIC, &stream->headers_submitted);
                h2_log_stream_diag(conn, stream, "headers-submitted", "wait=backend-error");
            }
        }
        if (rc != 0) {
            return rc;
        }
        if (stream->backend_state == H2_BACKEND_DONE || stream->backend_state == H2_BACKEND_FAILED) {
            stream->response_submitted = true;
            free(stream->raw_response);
            stream->raw_response = NULL;
            stream->raw_response_len = 0;
            stream->raw_response_cap = 0;
        }
    }
    return 0;
}

static void retry_delayed_loopbacks(h2_conn *conn) {
    for (h2_stream *stream = conn->streams; stream != NULL; stream = stream->next) {
        retry_delayed_loopback(conn, stream);
    }
}

static int h2_drive_session_send(nghttp2_session *session, h2_conn *conn) {
    (void)conn;
    int rc = nghttp2_session_send(session);
    if (rc == NGHTTP2_ERR_WOULDBLOCK) {
        return 0;
    }
    return rc;
}

static int count_backend_fds(const h2_conn *conn) {
    int count = 0;
    for (h2_stream *stream = conn->streams; stream != NULL; stream = stream->next) {
        if (stream->backend_fd >= 0) {
            count++;
        }
    }
    return count;
}

int rpsiod_http2_serve_connection(SSL *ssl, rpsiod_config *cfg, rpsiod_logger *logger,
                                  const char *client_ip, const char *server_ip, uint16_t local_port) {
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_session *session = NULL;
    h2_conn conn;
    memset(&conn, 0, sizeof(conn));
    conn.ssl = ssl;
    conn.cfg = cfg;
    conn.logger = logger;
    conn.local_port = local_port;
    rpsiod_safe_copy(conn.client_ip, sizeof(conn.client_ip), client_ip != NULL ? client_ip : "-");
    rpsiod_safe_copy(conn.server_ip, sizeof(conn.server_ip), server_ip != NULL ? server_ip : "0.0.0.0");

    if (nghttp2_session_callbacks_new(&callbacks) != 0) {
        return -1;
    }
    nghttp2_session_callbacks_set_send_callback(callbacks, ssl_send_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    if (nghttp2_session_server_new(&session, callbacks, &conn) != 0) {
        nghttp2_session_callbacks_del(callbacks);
        return -1;
    }
    nghttp2_session_callbacks_del(callbacks);

    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 128},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1048576},
    };
    if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings, 2) != 0 ||
        h2_drive_session_send(session, &conn) != 0) {
        nghttp2_session_del(session);
        free_all_streams(&conn);
        return -1;
    }

    unsigned char buf[16384];
    int ssl_fd = SSL_get_fd(ssl);
    int idle_ms = 0;
    bool close_requested = false;
    while (!close_requested &&
           (nghttp2_session_want_read(session) || nghttp2_session_want_write(session) || has_backend_work(&conn))) {
        if (submit_ready_streams(session, &conn) != 0) {
            break;
        }
        retry_delayed_loopbacks(&conn);
        if (nghttp2_session_want_write(session) && h2_drive_session_send(session, &conn) != 0) {
            break;
        }

        int backend_count = count_backend_fds(&conn);
        nfds_t nfds = (nfds_t)(backend_count + 1);
        struct pollfd *pfds = calloc(nfds, sizeof(*pfds));
        h2_stream **poll_streams = backend_count > 0 ? calloc((size_t)backend_count, sizeof(*poll_streams)) : NULL;
        if (pfds == NULL || (backend_count > 0 && poll_streams == NULL)) {
            free(pfds);
            free(poll_streams);
            break;
        }
        pfds[0].fd = ssl_fd;
        pfds[0].events = POLLIN;
        if (nghttp2_session_want_write(session)) {
            pfds[0].events |= POLLOUT;
        }
        nfds_t idx = 1;
        for (h2_stream *stream = conn.streams; stream != NULL; stream = stream->next) {
            if (stream->backend_fd < 0) {
                continue;
            }
            pfds[idx].fd = stream->backend_fd;
            if (stream->backend_state == H2_BACKEND_CONNECTING || stream->backend_state == H2_BACKEND_WRITING) {
                pfds[idx].events = POLLOUT;
            } else {
                pfds[idx].events = POLLIN;
            }
            poll_streams[idx - 1] = stream;
            idx++;
        }
        int timeout = has_active_streams(&conn) || has_backend_work(&conn) ? 10 : 100;
        int prc;
        do {
            prc = poll(pfds, nfds, timeout);
        } while (prc < 0 && errno == EINTR);
        if (prc < 0) {
            free(pfds);
            free(poll_streams);
            break;
        }
        if (prc == 0) {
            retry_delayed_loopbacks(&conn);
            if (!has_active_streams(&conn) && !has_backend_work(&conn)) {
                idle_ms += timeout;
                if (idle_ms >= H2_IDLE_TIMEOUT_MS) {
                    free(pfds);
                    free(poll_streams);
                    break;
                }
            }
            free(pfds);
            free(poll_streams);
            continue;
        }
        idle_ms = 0;

        if ((pfds[0].revents & POLLOUT) != 0 && nghttp2_session_want_write(session) &&
            h2_drive_session_send(session, &conn) != 0) {
            free(pfds);
            free(poll_streams);
            break;
        }
        if ((pfds[0].revents & POLLIN) != 0) {
            for (;;) {
                int n = SSL_read(ssl, buf, sizeof(buf));
                if (n > 0) {
                    ssize_t rv = nghttp2_session_mem_recv(session, buf, (size_t)n);
                    if (rv < 0) {
                        close_requested = true;
                        break;
                    }
                    continue;
                }
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    close_requested = true;
                    break;
                }
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
                    (err == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK))) {
                    break;
                }
                close_requested = true;
                break;
            }
        }
        for (nfds_t i = 1; i < idx; i++) {
            if (pfds[i].revents == 0) {
                continue;
            }
            (void)h2_progress_backend_stream(&conn, poll_streams[i - 1], pfds[i].revents);
        }
        free(pfds);
        free(poll_streams);

        if (submit_ready_streams(session, &conn) != 0) {
            break;
        }
        if (nghttp2_session_want_write(session) && h2_drive_session_send(session, &conn) != 0) {
            break;
        }
    }

    nghttp2_session_del(session);
    free_all_streams(&conn);
    return 0;
}
