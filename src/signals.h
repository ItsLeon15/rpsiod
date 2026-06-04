#ifndef RPSIOD_SIGNALS_H
#define RPSIOD_SIGNALS_H

#include <signal.h>
#include <stdbool.h>

extern volatile sig_atomic_t rpsiod_stop_requested;
extern volatile sig_atomic_t rpsiod_reload_requested;

void rpsiod_signal_stop(int sig);
void rpsiod_signal_reload(int sig);
void rpsiod_signals_install_parent(void);
void rpsiod_signals_install_worker(void);
int rpsiod_systemd_notify(const char *state);

#endif
