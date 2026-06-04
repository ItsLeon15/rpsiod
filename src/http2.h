#ifndef RPSIOD_HTTP2_H
#define RPSIOD_HTTP2_H

#include "config.h"
#include "log.h"

#include <openssl/ssl.h>
#include <stdint.h>

int rpsiod_http2_serve_connection(SSL *ssl, rpsiod_config *cfg, rpsiod_logger *logger,
                                  const char *client_ip, const char *server_ip, uint16_t local_port);

#endif
