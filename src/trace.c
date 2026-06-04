#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "trace.h"
#include "config.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct {
    const char *host;
    const char *path;
    const char *server_path;
    const char *sites_path;
    uint16_t port;
} trace_args;

static int parse_trace_args(int argc, char **argv, trace_args *args) {
    args->host = NULL;
    args->path = "/";
    args->server_path = "/etc/rpsiod/server.yml";
    args->sites_path = NULL;
    args->port = 0;
    if (argc < 1 || strcmp(argv[0], "request") != 0) {
        fprintf(stderr, "usage: rpsiod trace request --host example.com --path /pma/ [--port 80]\n");
        return -1;
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            args->host = argv[++i];
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            args->path = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            long port = strtol(argv[++i], NULL, 10);
            if (port > 0 && port <= 65535) {
                args->port = (uint16_t)port;
            }
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            args->server_path = argv[++i];
        } else if (strcmp(argv[i], "--sites") == 0 && i + 1 < argc) {
            args->sites_path = argv[++i];
        } else {
            fprintf(stderr, "unknown trace argument: %s\n", argv[i]);
            return -1;
        }
    }
    if (args->host == NULL || strlen(args->host) == 0) {
        fprintf(stderr, "trace request requires --host\n");
        return -1;
    }
    if (args->path[0] != '/') {
        fprintf(stderr, "trace request --path must start with /\n");
        return -1;
    }
    return 0;
}

static rpsiod_site_config *find_trace_site(rpsiod_config *cfg, const trace_args *args) {
    if (args->port != 0) {
        rpsiod_site_config *site = rpsiod_config_find_site(cfg, args->host, args->port);
        if (site != NULL) {
            return site;
        }
    }
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        if (!site->enabled || site->http_port == 0) {
            continue;
        }
        for (size_t d = 0; d < site->domain_count; d++) {
            if (rpsiod_streq_ci(site->domains[d], args->host)) {
                return site;
            }
        }
    }
    return NULL;
}

static int connect_site_http(const rpsiod_site_config *site, uint16_t override_port) {
    const char *ip = strcmp(site->listen_ip, "0.0.0.0") == 0 ? "127.0.0.1" : site->listen_ip;
    uint16_t port = override_port != 0 ? override_port : site->http_port;
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%u", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    if (getaddrinfo(ip, port_text, &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int run_trace_request(const trace_args *args) {
    rpsiod_config *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    char err[1024] = {0};
    if (rpsiod_config_load(cfg, args->server_path, args->sites_path, err, sizeof(err)) < 0) {
        fprintf(stderr, "config error: %s\n", err);
        free(cfg);
        return 1;
    }
    rpsiod_site_config *site = find_trace_site(cfg, args);
    if (site == NULL) {
        fprintf(stderr, "trace site not found for host %s\n", args->host);
        free(cfg);
        return 1;
    }
    int fd = connect_site_http(site, args->port);
    if (fd < 0) {
        fprintf(stderr, "failed to connect to %s:%u: %s\n",
                strcmp(site->listen_ip, "0.0.0.0") == 0 ? "127.0.0.1" : site->listen_ip,
                args->port != 0 ? args->port : site->http_port,
                strerror(errno));
        free(cfg);
        return 1;
    }
    char request[4096];
    int n = snprintf(request, sizeof(request),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: rpsiod-trace/1.0\r\n"
                     "Accept: */*\r\n"
                     "X-Rpsiod-Trace: 1\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     args->path,
                     args->host);
    if (n < 0 || (size_t)n >= sizeof(request) || rpsiod_write_all(fd, request, (size_t)n) < 0) {
        fprintf(stderr, "failed to send trace request\n");
        close(fd);
        free(cfg);
        return 1;
    }
    char buf[32768];
    size_t total = 0;
    bool printed_headers = false;
    for (;;) {
        ssize_t rd = read(fd, buf, sizeof(buf));
        if (rd < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "failed to read trace response: %s\n", strerror(errno));
            close(fd);
            free(cfg);
            return 1;
        }
        if (rd == 0) {
            break;
        }
        total += (size_t)rd;
        if (!printed_headers) {
            char *end = memmem(buf, (size_t)rd, "\r\n\r\n", 4);
            if (end != NULL) {
                size_t header_len = (size_t)(end - buf) + 4;
                (void)fwrite(buf, 1, header_len, stdout);
                printed_headers = true;
            }
        }
    }
    close(fd);
    printf("trace response bytes: %zu\n", total);
    printf("server trace: written to configured error log for host %s\n", args->host);
    free(cfg);
    return 0;
}

int rpsiod_trace_main(int argc, char **argv) {
    trace_args args;
    if (parse_trace_args(argc, argv, &args) < 0) {
        return 2;
    }
    return run_trace_request(&args);
}
