#ifndef RPSIOD_TLS_H
#define RPSIOD_TLS_H

#include "config.h"
#include "log.h"

#include <openssl/ssl.h>

SSL_CTX *rpsiod_tls_create_context(rpsiod_config *cfg, rpsiod_logger *logger);
int rpsiod_tls_validate_material(rpsiod_config *cfg, char *err, size_t err_len);
bool rpsiod_tls_selected_http2(SSL *ssl);

#endif
