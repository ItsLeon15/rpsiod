#ifndef RPSIOD_COMPRESS_H
#define RPSIOD_COMPRESS_H

#include <stdbool.h>
#include <stddef.h>

bool rpsiod_accepts_gzip(const char *accept_encoding);
bool rpsiod_accepts_br(const char *accept_encoding);
bool rpsiod_content_type_compressible(const char *content_type);
bool rpsiod_path_already_compressed(const char *path);
int rpsiod_gzip_compress(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len);
int rpsiod_gzip_store(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len);
int rpsiod_brotli_compress(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len);

#endif
