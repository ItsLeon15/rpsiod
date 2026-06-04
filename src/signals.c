#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "signals.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

volatile sig_atomic_t rpsiod_stop_requested = 0;
volatile sig_atomic_t rpsiod_reload_requested = 0;

void rpsiod_signal_stop(int sig) {
    (void)sig;
    rpsiod_stop_requested = 1;
}

void rpsiod_signal_reload(int sig) {
    (void)sig;
    rpsiod_reload_requested = 1;
}

void rpsiod_signals_install_parent(void) {
    signal(SIGINT, rpsiod_signal_stop);
    signal(SIGTERM, rpsiod_signal_stop);
    signal(SIGHUP, rpsiod_signal_reload);
    signal(SIGPIPE, SIG_IGN);
}

void rpsiod_signals_install_worker(void) {
    signal(SIGINT, rpsiod_signal_stop);
    signal(SIGTERM, rpsiod_signal_stop);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
}

int rpsiod_systemd_notify(const char *state) {
    const char *sock_path = getenv("NOTIFY_SOCKET");
    if (sock_path == NULL || sock_path[0] == '\0' || state == NULL) {
        return 0;
    }
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t len = strlen(sock_path);
    if (sock_path[0] == '@') {
        addr.sun_path[0] = '\0';
        if (len >= sizeof(addr.sun_path)) {
            close(fd);
            return -1;
        }
        memcpy(addr.sun_path + 1, sock_path + 1, len - 1);
    } else {
        if (len >= sizeof(addr.sun_path)) {
            close(fd);
            return -1;
        }
        memcpy(addr.sun_path, sock_path, len + 1);
    }
    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len + (sock_path[0] == '@' ? 0 : 1));
    ssize_t sent = sendto(fd, state, strlen(state), MSG_NOSIGNAL, (struct sockaddr *)&addr, addr_len);
    close(fd);
    return sent < 0 ? -1 : 0;
}
