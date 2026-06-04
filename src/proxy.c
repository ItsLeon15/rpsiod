#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "proxy.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static bool request_header_name_is(const char *line, size_t line_len, const char *name) {
    size_t name_len = strlen(name);
    if (line_len <= name_len || line[name_len] != ':') {
        return false;
    }
    for (size_t i = 0; i < name_len; i++) {
        if (tolower((unsigned char)line[i]) != tolower((unsigned char)name[i])) {
            return false;
        }
    }
    return true;
}

bool rpsiod_proxy_skip_header(const char *line, size_t line_len) {
    return request_header_name_is(line, line_len, "Host") ||
           request_header_name_is(line, line_len, "Connection") ||
           request_header_name_is(line, line_len, "Proxy-Connection") ||
           request_header_name_is(line, line_len, "X-Real-IP") ||
           request_header_name_is(line, line_len, "X-Forwarded-For") ||
           request_header_name_is(line, line_len, "X-Forwarded-Proto");
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_sec) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    int rc = connect(fd, addr, addr_len);
    if (rc < 0 && errno != EINPROGRESS) {
        return -1;
    }
    if (rc < 0) {
        struct pollfd poll_fd = {.fd = fd, .events = POLLOUT};
        int timeout_ms = timeout_sec > 0 ? timeout_sec * 1000 : 5000;
        do {
            rc = poll(&poll_fd, 1, timeout_ms);
        } while (rc < 0 && errno == EINTR);
        if (rc <= 0) {
            errno = rc == 0 ? ETIMEDOUT : errno;
            return -1;
        }
        int socket_error = 0;
        socklen_t socket_error_len = sizeof(socket_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len) < 0 || socket_error != 0) {
            errno = socket_error != 0 ? socket_error : errno;
            return -1;
        }
    }
    return fcntl(fd, F_SETFL, flags);
}

int rpsiod_proxy_connect(const rpsiod_site_config *site) {
    char port[16];
    snprintf(port, sizeof(port), "%u", site->proxy_port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(site->proxy_host, port, &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        struct timeval tv;
        tv.tv_sec = site->proxy_read_timeout_sec;
        tv.tv_usec = 0;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        tv.tv_sec = site->proxy_write_timeout_sec;
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, site->proxy_connect_timeout_sec) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int rpsiod_proxy_parse_response_status(const char *buf, size_t len) {
    if (len < 12 || strncmp(buf, "HTTP/", 5) != 0) {
        return 502;
    }
    const char *space = memchr(buf, ' ', len);
    if (space == NULL || space + 4 > buf + len) {
        return 502;
    }
    int status = atoi(space + 1);
    return status > 0 ? status : 502;
}
