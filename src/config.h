#ifndef RPSIOD_CONFIG_H
#define RPSIOD_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define RPSIOD_MAX_SITES 64
#define RPSIOD_MAX_DOMAINS 32
#define RPSIOD_MAX_INDEXES 16
#define RPSIOD_MAX_METHODS 16
#define RPSIOD_MAX_BLOCKED 64
#define RPSIOD_MAX_ERROR_PAGES 16
#define RPSIOD_MAX_HEADERS 32
#define RPSIOD_MAX_HEADER_REMOVES 32
#define RPSIOD_RATE_BUCKETS 1024
#define RPSIOD_STATIC_META_CACHE 128
#define RPSIOD_ROUTE_TABLE_SIZE 4096
#define RPSIOD_OPEN_FILE_CACHE_MAX 256

typedef struct {
    int code;
    char path[512];
} rpsiod_error_page;

typedef struct {
    bool enabled;
    char path[512];
    int fd;
} rpsiod_log_path;

typedef struct {
    char name[128];
    char value[512];
} rpsiod_header_pair;

typedef struct {
    uint32_t ip;
    uint64_t window_start;
    uint32_t count;
} rpsiod_rate_bucket;

typedef struct {
    bool valid;
    char relative_path[512];
    char absolute_path[4096];
    char mime[96];
    char etag[128];
    off_t size;
    time_t mtime;
    unsigned long long inode;
    bool blocked;
    bool directory;
    bool has_br;
    bool has_gzip;
    off_t br_size;
    off_t gzip_size;
    time_t br_mtime;
    time_t gzip_mtime;
    unsigned long long br_inode;
    unsigned long long gzip_inode;
} rpsiod_static_meta_cache_entry;

typedef struct {
    bool valid;
    char relative_path[512];
    int fd;
    off_t size;
    time_t mtime;
    unsigned long long inode;
    unsigned long long last_used;
} rpsiod_open_file_cache_entry;

typedef struct {
    bool used;
    bool default_site;
    char host[256];
    char listen_ip[64];
    uint16_t port;
    size_t site_index;
} rpsiod_route_entry;

typedef struct {
    char name[128];
    bool enabled;
    char serve_as[16];

    char domains[RPSIOD_MAX_DOMAINS][256];
    size_t domain_count;

    char listen_ip[64];
    uint16_t http_port;
    uint16_t https_port;

    char routing_type[32];

    bool redirect_http_to_https;
    bool redirect_www_enabled;
    char redirect_www_mode[32];
    int redirect_www_status;

    bool ssl_enabled;
    char ssl_mode[32];
    char ssl_provider[64];
    char ssl_email[256];
    char ssl_storage[512];
    char ssl_challenge[32];
    int ssl_renew_before_sec;

    char static_root[512];
    char static_root_real[4096];
    int static_root_fd;
    rpsiod_static_meta_cache_entry static_meta_cache[RPSIOD_STATIC_META_CACHE];
    size_t static_meta_clock;
    rpsiod_open_file_cache_entry open_file_cache[RPSIOD_OPEN_FILE_CACHE_MAX];
    size_t open_file_cache_clock;
    size_t open_file_cache_count;
    unsigned long long open_file_cache_tick;
    char indexes[RPSIOD_MAX_INDEXES][128];
    size_t index_count;
    char fallback[256];
    bool directory_listing;

    bool maintenance_enabled;
    int maintenance_status;
    char maintenance_page[512];

    rpsiod_error_page error_pages[RPSIOD_MAX_ERROR_PAGES];
    size_t error_page_count;

    uint64_t max_body_size;
    bool hide_server_header;
    bool allow_symlinks;
    char allowed_methods[RPSIOD_MAX_METHODS][16];
    size_t allowed_method_count;

    char blocked_direct_access[RPSIOD_MAX_BLOCKED][128];
    size_t blocked_direct_access_count;

    bool php_enabled;
    char php_handler_type[32];
    char php_socket[256];
    char php_host[256];
    uint16_t php_port;
    bool php_allow_path_info;
    int php_connect_timeout_sec;
    int php_read_timeout_sec;
    int php_write_timeout_sec;
    uint64_t php_max_body_size;
    int php_max_execution_time_sec;

    bool rate_limit_enabled;
    uint32_t rate_limit_requests;
    int rate_limit_window_sec;
    rpsiod_rate_bucket rate_buckets[RPSIOD_RATE_BUCKETS];

    bool compression_enabled;
    bool compression_gzip;
    bool compression_br;
    uint64_t compression_minimum_size;

    bool cache_enabled;
    char cache_default[256];

    rpsiod_header_pair headers_add[RPSIOD_MAX_HEADERS];
    size_t headers_add_count;
    char headers_remove[RPSIOD_MAX_HEADER_REMOVES][128];
    size_t headers_remove_count;

    char proxy_scheme[16];
    char proxy_host[256];
    uint16_t proxy_port;
    bool proxy_websocket;
    bool proxy_pass_host;
    bool proxy_real_ip;
    bool proxy_forwarded_for;
    bool proxy_forwarded_proto;
    int proxy_connect_timeout_sec;
    int proxy_read_timeout_sec;
    int proxy_write_timeout_sec;
    bool proxy_health_enabled;
    char proxy_health_path[256];

    rpsiod_log_path access_log;
    rpsiod_log_path error_log;
} rpsiod_site_config;

typedef struct {
    char name[64];
    char environment[64];

    char linux_user[64];
    char linux_group[64];
    char pid_file[256];
    bool reuse_port;
    bool tcp_fast_open;
    int backlog;
    uint64_t open_files;
    uint64_t max_processes;

    int workers;
    bool workers_auto;
    uint64_t max_connections;
    bool keep_alive_enabled;
    int keep_alive_timeout_sec;
    int keep_alive_max_requests;
    size_t request_header_buffer;
    size_t response_buffer;
    bool sendfile_enabled;
    bool read_ahead_enabled;
    bool open_file_cache_enabled;
    size_t open_file_cache_max;

    bool hide_version;
    bool drop_privileges;
    bool prevent_core_dumps;

    char logging_level[32];
    char logging_format[32];
    rpsiod_log_path access_log;
    rpsiod_log_path error_log;

    bool benchmarks_enabled;
    char benchmarks_ip[64];
    uint16_t benchmarks_port;
    char benchmarks_storage_path[512];

    char server_file[512];
    char sites_file[512];
    char loaded_sites_file[512];
    bool parse_failed;
    char parse_error[512];

    bool chroot_enabled;
    char chroot_path[512];

    rpsiod_site_config sites[RPSIOD_MAX_SITES];
    size_t site_count;
    rpsiod_route_entry route_table[RPSIOD_ROUTE_TABLE_SIZE];
    size_t route_count;
} rpsiod_config;

void rpsiod_config_defaults(rpsiod_config *cfg);
int rpsiod_config_load(rpsiod_config *cfg, const char *server_path, const char *sites_path, char *err, size_t err_len);
int rpsiod_config_validate(rpsiod_config *cfg, char *err, size_t err_len);
rpsiod_site_config *rpsiod_config_find_site(rpsiod_config *cfg, const char *host, uint16_t port);
rpsiod_site_config *rpsiod_config_find_site_for_listener(rpsiod_config *cfg, const char *host, uint16_t port, const char *listen_ip);
void rpsiod_config_close_site_caches(rpsiod_config *cfg);
bool rpsiod_site_allows_method(const rpsiod_site_config *site, const char *method);
const char *rpsiod_site_error_page(const rpsiod_site_config *site, int status);

#endif
