#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "php.h"
#include "util.h"

#include <limits.h>
#include <string.h>

static bool ascii_streq_ci_n(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char ac = (unsigned char)a[i];
        unsigned char bc = (unsigned char)b[i];
        if (ac >= 'A' && ac <= 'Z') ac = (unsigned char)(ac + ('a' - 'A'));
        if (bc >= 'A' && bc <= 'Z') bc = (unsigned char)(bc + ('a' - 'A'));
        if (ac != bc) {
            return false;
        }
    }
    return b[len] == '\0';
}

static bool path_has_suffix_ci(const char *path, size_t path_len, const char *suffix) {
    size_t suffix_len = strlen(suffix);
    return path_len >= suffix_len &&
           ascii_streq_ci_n(path + path_len - suffix_len, suffix, suffix_len);
}

static size_t clean_path_copy(char *out, size_t out_len, const char *path) {
    rpsiod_safe_copy(out, out_len, path);
    char *query = strchr(out, '?');
    if (query != NULL) {
        *query = '\0';
    }
    return strlen(out);
}

static bool path_has_php_source_extension(const char *path, size_t path_len) {
    static const char *const php_exts[] = {
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".php7",
        ".php8",
        ".phtml",
        ".pht",
        ".phps",
        NULL
    };
    for (size_t i = 0; php_exts[i] != NULL; i++) {
        if (path_has_suffix_ci(path, path_len, php_exts[i])) {
            return true;
        }
    }
    return false;
}

bool rpsiod_php_path_is_php(const char *path) {
    if (path == NULL) {
        return false;
    }
    char clean[PATH_MAX];
    size_t len = clean_path_copy(clean, sizeof(clean), path);
    return path_has_suffix_ci(clean, len, ".php") ||
           path_has_suffix_ci(clean, len, ".php3") ||
           path_has_suffix_ci(clean, len, ".php4") ||
           path_has_suffix_ci(clean, len, ".php5") ||
           path_has_suffix_ci(clean, len, ".php7") ||
           path_has_suffix_ci(clean, len, ".php8") ||
           path_has_suffix_ci(clean, len, ".phtml") ||
           path_has_suffix_ci(clean, len, ".pht");
}

bool rpsiod_php_path_is_source_like(const char *path) {
    if (path == NULL) {
        return false;
    }
    static const char *const peel_suffixes[] = {
        ".br",
        ".gz",
        ".zst",
        ".bak",
        ".backup",
        ".old",
        ".orig",
        ".save",
        ".swp",
        ".swo",
        ".tmp",
        ".copy",
        ".dist",
        NULL
    };
    char clean[PATH_MAX];
    size_t len = clean_path_copy(clean, sizeof(clean), path);
    for (;;) {
        bool peeled = false;
        if (len > 0 && clean[len - 1] == '~') {
            clean[--len] = '\0';
            peeled = true;
        } else {
            for (size_t i = 0; peel_suffixes[i] != NULL; i++) {
                if (path_has_suffix_ci(clean, len, peel_suffixes[i])) {
                    len -= strlen(peel_suffixes[i]);
                    clean[len] = '\0';
                    peeled = true;
                    break;
                }
            }
        }
        if (!peeled) {
            break;
        }
    }
    return path_has_php_source_extension(clean, len);
}
