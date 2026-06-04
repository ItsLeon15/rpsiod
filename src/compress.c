#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "compress.h"
#include "util.h"

#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint32_t crc32_update(uint32_t crc, const unsigned char *data, size_t len) {
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

typedef unsigned char z_byte;
typedef unsigned int z_uint;
typedef unsigned long z_ulong;
typedef void *z_voidp;
typedef z_voidp (*z_alloc_func)(z_voidp opaque, z_uint items, z_uint size);
typedef void (*z_free_func)(z_voidp opaque, z_voidp address);

typedef struct {
    z_byte *next_in;
    z_uint avail_in;
    z_ulong total_in;
    z_byte *next_out;
    z_uint avail_out;
    z_ulong total_out;
    char *msg;
    void *state;
    z_alloc_func zalloc;
    z_free_func zfree;
    z_voidp opaque;
    int data_type;
    z_ulong adler;
    z_ulong reserved;
} rpsiod_z_stream;

typedef const char *(*zlib_version_fn)(void);
typedef int (*deflate_init2_fn)(rpsiod_z_stream *strm, int level, int method, int window_bits, int mem_level, int strategy, const char *version, int stream_size);
typedef int (*deflate_fn)(rpsiod_z_stream *strm, int flush);
typedef int (*deflate_end_fn)(rpsiod_z_stream *strm);

static void load_symbol_fn(void *dst, size_t dst_len, void *symbol) {
    memset(dst, 0, dst_len);
    memcpy(dst, &symbol, dst_len < sizeof(symbol) ? dst_len : sizeof(symbol));
}

int rpsiod_gzip_compress(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len) {
    void *libz = dlopen("libz.so.1", RTLD_LAZY | RTLD_LOCAL);
    if (libz == NULL) {
        return -1;
    }
    zlib_version_fn zlib_version;
    deflate_init2_fn deflate_init2;
    deflate_fn z_deflate;
    deflate_end_fn deflate_end;
    load_symbol_fn(&zlib_version, sizeof(zlib_version), dlsym(libz, "zlibVersion"));
    load_symbol_fn(&deflate_init2, sizeof(deflate_init2), dlsym(libz, "deflateInit2_"));
    load_symbol_fn(&z_deflate, sizeof(z_deflate), dlsym(libz, "deflate"));
    load_symbol_fn(&deflate_end, sizeof(deflate_end), dlsym(libz, "deflateEnd"));
    if (zlib_version == NULL || deflate_init2 == NULL || z_deflate == NULL || deflate_end == NULL) {
        dlclose(libz);
        return -1;
    }

    size_t cap = in_len + (in_len / 8U) + 1024U;
    if (cap < 4096U) {
        cap = 4096U;
    }
    unsigned char *buf = malloc(cap);
    if (buf == NULL) {
        dlclose(libz);
        return -1;
    }

    rpsiod_z_stream zs;
    memset(&zs, 0, sizeof(zs));
    zs.next_in = (z_byte *)in;
    zs.avail_in = in_len > UINT_MAX ? UINT_MAX : (z_uint)in_len;
    zs.next_out = buf;
    zs.avail_out = cap > UINT_MAX ? UINT_MAX : (z_uint)cap;

    enum {
        RPSIOD_Z_OK = 0,
        RPSIOD_Z_STREAM_END = 1,
        RPSIOD_Z_FINISH = 4,
        RPSIOD_Z_DEFLATED = 8,
        RPSIOD_Z_DEFAULT_COMPRESSION = -1,
        RPSIOD_Z_DEFAULT_STRATEGY = 0
    };
    if (deflate_init2(&zs, RPSIOD_Z_DEFAULT_COMPRESSION, RPSIOD_Z_DEFLATED, 31, 8, RPSIOD_Z_DEFAULT_STRATEGY, zlib_version(), (int)sizeof(zs)) != RPSIOD_Z_OK) {
        free(buf);
        dlclose(libz);
        return -1;
    }

    int rc = z_deflate(&zs, RPSIOD_Z_FINISH);
    if (rc != RPSIOD_Z_STREAM_END) {
        (void)deflate_end(&zs);
        free(buf);
        dlclose(libz);
        return -1;
    }
    (void)deflate_end(&zs);
    *out = buf;
    *out_len = (size_t)zs.total_out;
    dlclose(libz);
    return 0;
}

int rpsiod_gzip_store(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len) {
    size_t blocks = (in_len + 65534U) / 65535U;
    size_t cap = 10U + blocks * 5U + in_len + 8U;
    unsigned char *buf = malloc(cap);
    if (buf == NULL) {
        return -1;
    }
    size_t p = 0;
    buf[p++] = 0x1f;
    buf[p++] = 0x8b;
    buf[p++] = 0x08;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x03;
    size_t pos = 0;
    while (pos < in_len || (in_len == 0 && pos == 0)) {
        size_t chunk = in_len - pos;
        if (chunk > 65535U) {
            chunk = 65535U;
        }
        bool final = pos + chunk >= in_len;
        buf[p++] = final ? 0x01 : 0x00;
        uint16_t len16 = (uint16_t)chunk;
        uint16_t nlen16 = (uint16_t)~len16;
        buf[p++] = (unsigned char)(len16 & 0xffU);
        buf[p++] = (unsigned char)((len16 >> 8) & 0xffU);
        buf[p++] = (unsigned char)(nlen16 & 0xffU);
        buf[p++] = (unsigned char)((nlen16 >> 8) & 0xffU);
        if (chunk > 0) {
            memcpy(buf + p, in + pos, chunk);
            p += chunk;
        }
        pos += chunk;
        if (in_len == 0) {
            break;
        }
    }
    uint32_t crc = crc32_update(0, in, in_len);
    uint32_t isize = (uint32_t)(in_len & 0xffffffffU);
    for (int i = 0; i < 4; i++) {
        buf[p++] = (unsigned char)((crc >> (i * 8)) & 0xffU);
    }
    for (int i = 0; i < 4; i++) {
        buf[p++] = (unsigned char)((isize >> (i * 8)) & 0xffU);
    }
    *out = buf;
    *out_len = p;
    return 0;
}

typedef size_t (*brotli_max_compressed_size_fn)(size_t input_size);
typedef int (*brotli_compress_fn)(int quality, int lgwin, int mode, size_t input_size, const unsigned char input_buffer[], size_t *encoded_size, unsigned char encoded_buffer[]);

int rpsiod_brotli_compress(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len) {
    void *libbr = dlopen("libbrotlienc.so.1", RTLD_LAZY | RTLD_LOCAL);
    if (libbr == NULL) {
        return -1;
    }
    brotli_max_compressed_size_fn max_size;
    brotli_compress_fn compress;
    load_symbol_fn(&max_size, sizeof(max_size), dlsym(libbr, "BrotliEncoderMaxCompressedSize"));
    load_symbol_fn(&compress, sizeof(compress), dlsym(libbr, "BrotliEncoderCompress"));
    if (max_size == NULL || compress == NULL) {
        dlclose(libbr);
        return -1;
    }
    size_t cap = max_size(in_len);
    if (cap == 0) {
        cap = in_len + 1024U;
    }
    unsigned char *buf = malloc(cap);
    if (buf == NULL) {
        dlclose(libbr);
        return -1;
    }
    size_t encoded = cap;
    if (!compress(5, 22, 1, in_len, in, &encoded, buf)) {
        free(buf);
        dlclose(libbr);
        return -1;
    }
    *out = buf;
    *out_len = encoded;
    dlclose(libbr);
    return 0;
}

static bool is_ows(char ch) {
    return ch == ' ' || ch == '\t';
}

static bool token_eq_ci(const char *token, size_t token_len, const char *expected) {
    size_t expected_len = strlen(expected);
    if (token_len != expected_len) {
        return false;
    }
    for (size_t i = 0; i < token_len; i++) {
        unsigned char a = (unsigned char)token[i];
        unsigned char b = (unsigned char)expected[i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + ('a' - 'A'));
        if (a != b) {
            return false;
        }
    }
    return true;
}

static bool qvalue_is_zero(const char *value, size_t value_len) {
    while (value_len > 0 && is_ows(*value)) {
        value++;
        value_len--;
    }
    while (value_len > 0 && is_ows(value[value_len - 1])) {
        value_len--;
    }
    if (value_len == 0 || value[0] != '0') {
        return false;
    }
    bool dot_seen = false;
    for (size_t i = 1; i < value_len; i++) {
        if (value[i] == '.') {
            if (dot_seen) {
                return false;
            }
            dot_seen = true;
            continue;
        }
        if (value[i] != '0') {
            return false;
        }
    }
    return true;
}

static bool accept_encoding_token_allowed(const char *params, size_t params_len) {
    bool allowed = true;
    size_t i = 0;
    while (i < params_len) {
        while (i < params_len && (params[i] == ';' || is_ows(params[i]))) {
            i++;
        }
        size_t name_start = i;
        while (i < params_len && params[i] != '=' && params[i] != ';') {
            i++;
        }
        size_t name_end = i;
        while (name_end > name_start && is_ows(params[name_end - 1])) {
            name_end--;
        }
        if (i >= params_len || params[i] != '=') {
            while (i < params_len && params[i] != ';') {
                i++;
            }
            continue;
        }
        i++;
        while (i < params_len && is_ows(params[i])) {
            i++;
        }
        size_t value_start = i;
        while (i < params_len && params[i] != ';') {
            i++;
        }
        size_t value_end = i;
        if (token_eq_ci(params + name_start, name_end - name_start, "q")) {
            allowed = !qvalue_is_zero(params + value_start, value_end - value_start);
        }
    }
    return allowed;
}

static bool accepts_encoding_token(const char *accept_encoding, const char *encoding) {
    if (accept_encoding == NULL || accept_encoding[0] == '\0') {
        return false;
    }
    const char *p = accept_encoding;
    while (*p != '\0') {
        while (*p == ',' || is_ows(*p)) {
            p++;
        }
        const char *item_start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        const char *item_end = p;
        while (item_end > item_start && is_ows(item_end[-1])) {
            item_end--;
        }
        const char *token_end = item_start;
        while (token_end < item_end && *token_end != ';' && !is_ows(*token_end)) {
            token_end++;
        }
        const char *params = token_end;
        while (params < item_end && is_ows(*params)) {
            params++;
        }
        if (token_eq_ci(item_start, (size_t)(token_end - item_start), encoding)) {
            return accept_encoding_token_allowed(params, (size_t)(item_end - params));
        }
    }
    return false;
}

bool rpsiod_accepts_gzip(const char *accept_encoding) {
    return accepts_encoding_token(accept_encoding, "gzip");
}

bool rpsiod_accepts_br(const char *accept_encoding) {
    return accepts_encoding_token(accept_encoding, "br");
}

bool rpsiod_content_type_compressible(const char *content_type) {
    return rpsiod_starts_with(content_type, "text/") ||
           strstr(content_type, "javascript") != NULL ||
           strstr(content_type, "json") != NULL ||
           strstr(content_type, "xml") != NULL ||
           strstr(content_type, "svg") != NULL;
}

bool rpsiod_path_already_compressed(const char *path) {
    const char *ext = strrchr(path, '.');
    return ext != NULL &&
           (rpsiod_streq_ci(ext, ".gz") ||
            rpsiod_streq_ci(ext, ".br") ||
            rpsiod_streq_ci(ext, ".zip") ||
            rpsiod_streq_ci(ext, ".png") ||
            rpsiod_streq_ci(ext, ".jpg") ||
            rpsiod_streq_ci(ext, ".jpeg") ||
            rpsiod_streq_ci(ext, ".gif") ||
            rpsiod_streq_ci(ext, ".webp") ||
            rpsiod_streq_ci(ext, ".ico") ||
            rpsiod_streq_ci(ext, ".pdf"));
}
