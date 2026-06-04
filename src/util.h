#ifndef RPSIOD_UTIL_H
#define RPSIOD_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int rpsiod_set_nonblocking(int fd);
int rpsiod_mkdir_parent(const char *path);
int rpsiod_open_append(const char *path);
void rpsiod_trim(char *s);
bool rpsiod_streq_ci(const char *a, const char *b);
bool rpsiod_starts_with(const char *s, const char *prefix);
uint64_t rpsiod_parse_size(const char *text, uint64_t fallback);
int rpsiod_parse_duration_sec(const char *text, int fallback);
bool rpsiod_parse_bool(const char *text, bool fallback);
int rpsiod_percent_decode_path(const char *in, char *out, size_t out_len);
bool rpsiod_path_has_forbidden_segment(const char *path);
bool rpsiod_path_join(char *out, size_t out_len, const char *root, const char *request_path);
bool rpsiod_path_within_root(const char *root_real, const char *target_real);
const char *rpsiod_mime_type(const char *path);
void rpsiod_strip_port(char *host);
void rpsiod_safe_copy(char *dst, size_t dst_len, const char *src);
int rpsiod_write_all(int fd, const void *buf, size_t len);
int rpsiod_drop_core_dumps(void);
int rpsiod_write_pid_file(const char *path);

#endif
