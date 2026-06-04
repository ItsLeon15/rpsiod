#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "tls.h"
#include "util.h"

#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void tls_set_err(char *err, size_t err_len, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void tls_set_err(char *err, size_t err_len, const char *fmt, ...) {
    if (err_len == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    static const unsigned char h2[] = {'h', '2'};
    static const unsigned char http11[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};

    const unsigned char *p = in;
    const unsigned char *end = in + inlen;
    while (p < end) {
        unsigned int len = *p++;
        if ((size_t)(end - p) < len) {
            break;
        }
        if (len == sizeof(h2) && memcmp(p, h2, sizeof(h2)) == 0) {
            *out = h2;
            *outlen = (unsigned char)sizeof(h2);
            return SSL_TLSEXT_ERR_OK;
        }
        p += len;
    }

    p = in;
    while (p < end) {
        unsigned int len = *p++;
        if ((size_t)(end - p) < len) {
            break;
        }
        if (len == sizeof(http11) && memcmp(p, http11, sizeof(http11)) == 0) {
            *out = http11;
            *outlen = (unsigned char)sizeof(http11);
            return SSL_TLSEXT_ERR_OK;
        }
        p += len;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

bool rpsiod_tls_selected_http2(SSL *ssl) {
    const unsigned char *proto = NULL;
    unsigned int proto_len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &proto_len);
    return proto_len == 2 && proto != NULL && memcmp(proto, "h2", 2) == 0;
}

static int ensure_auto_certificate(const rpsiod_site_config *site, char *cert_path, size_t cert_len, char *key_path, size_t key_len, rpsiod_logger *logger) {
    if (snprintf(cert_path, cert_len, "%s/cert.pem", site->ssl_storage) >= (int)cert_len ||
        snprintf(key_path, key_len, "%s/key.pem", site->ssl_storage) >= (int)key_len) {
        return -1;
    }
    if (access(cert_path, R_OK) == 0 && access(key_path, R_OK) == 0) {
        return 0;
    }
    if (!rpsiod_streq_ci(site->ssl_mode, "auto")) {
        return -1;
    }
    if (rpsiod_mkdir_parent(cert_path) < 0 || rpsiod_mkdir_parent(key_path) < 0) {
        return -1;
    }
    (void)chmod(site->ssl_storage, 0700);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    int rc = -1;
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        goto out;
    }
    x509 = X509_new();
    if (x509 == NULL) {
        goto out;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)time(NULL));
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 90L * 86400L);
    X509_set_pubkey(x509, pkey);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)site->domains[0], -1, -1, 0);
    X509_set_issuer_name(x509, name);

    char san[1024] = {0};
    size_t used = 0;
    for (size_t i = 0; i < site->domain_count; i++) {
        int n = snprintf(san + used, sizeof(san) - used, "%sDNS:%s", i == 0 ? "" : ",", site->domains[i]);
        if (n < 0 || (size_t)n >= sizeof(san) - used) {
            break;
        }
        used += (size_t)n;
    }
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
    if (ext != NULL) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (X509_sign(x509, pkey, EVP_sha256()) <= 0) {
        goto out;
    }
    int key_fd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (key_fd < 0) goto out;
    (void)fchmod(key_fd, 0600);
    FILE *kf = fdopen(key_fd, "w");
    if (kf == NULL) {
        close(key_fd);
        goto out;
    }
    bool key_ok = PEM_write_PrivateKey(kf, pkey, NULL, NULL, 0, NULL, NULL) == 1;
    fclose(kf);
    int cert_fd = open(cert_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (cert_fd < 0) goto out;
    (void)fchmod(cert_fd, 0644);
    FILE *cf = fdopen(cert_fd, "w");
    if (cf == NULL) {
        close(cert_fd);
        goto out;
    }
    bool cert_ok = PEM_write_X509(cf, x509) == 1;
    fclose(cf);
    if (!key_ok || !cert_ok) {
        goto out;
    }
    rpsiod_log_error(logger, NULL, "generated automatic local TLS certificate for site '%s' in %s", site->name, site->ssl_storage);
    rc = 0;
out:
    if (rc != 0) {
        rpsiod_log_error(logger, NULL, "failed to generate automatic TLS certificate for site '%s'", site->name);
    }
    X509_free(x509);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

static int tls_paths_for_site(const rpsiod_site_config *site, char *cert_path, size_t cert_len, char *key_path, size_t key_len) {
    if (snprintf(cert_path, cert_len, "%s/cert.pem", site->ssl_storage) >= (int)cert_len ||
        snprintf(key_path, key_len, "%s/key.pem", site->ssl_storage) >= (int)key_len) {
        return -1;
    }
    return 0;
}

static int validate_tls_pair(const rpsiod_site_config *site, const char *cert_path, const char *key_path, char *err, size_t err_len) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        tls_set_err(err, err_len, "site '%s': failed to allocate TLS context", site->name);
        return -1;
    }
    int ok = SSL_CTX_use_certificate_chain_file(ctx, cert_path) == 1 &&
             SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) == 1 &&
             SSL_CTX_check_private_key(ctx) == 1;
    SSL_CTX_free(ctx);
    if (!ok) {
        tls_set_err(err, err_len, "site '%s': invalid TLS cert/key in %s", site->name, site->ssl_storage);
        ERR_clear_error();
        return -1;
    }
    struct stat st;
    if (stat(key_path, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        tls_set_err(err, err_len, "site '%s': TLS private key must not be group/world accessible: %s", site->name, key_path);
        return -1;
    }
    return 0;
}

int rpsiod_tls_validate_material(rpsiod_config *cfg, char *err, size_t err_len) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        if (!site->enabled || !site->ssl_enabled) {
            continue;
        }
        char cert_path[PATH_MAX];
        char key_path[PATH_MAX];
        if (tls_paths_for_site(site, cert_path, sizeof(cert_path), key_path, sizeof(key_path)) < 0) {
            tls_set_err(err, err_len, "site '%s': TLS cert/key paths are too long", site->name);
            return -1;
        }
        bool cert_exists = access(cert_path, F_OK) == 0;
        bool key_exists = access(key_path, F_OK) == 0;
        if (cert_exists != key_exists) {
            tls_set_err(err, err_len, "site '%s': TLS cert/key must either both exist or both be absent in %s", site->name, site->ssl_storage);
            return -1;
        }
        if (!cert_exists) {
            if (rpsiod_streq_ci(site->ssl_mode, "auto")) {
                continue;
            }
            tls_set_err(err, err_len, "site '%s': TLS cert/key missing in %s", site->name, site->ssl_storage);
            return -1;
        }
        if (validate_tls_pair(site, cert_path, key_path, err, err_len) < 0) {
            return -1;
        }
    }
    return 0;
}

SSL_CTX *rpsiod_tls_create_context(rpsiod_config *cfg, rpsiod_logger *logger) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    char err[512] = {0};
    if (rpsiod_tls_validate_material(cfg, err, sizeof(err)) < 0) {
        rpsiod_log_error(logger, NULL, "%s", err);
        SSL_CTX_free(ctx);
        return NULL;
    }
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        if (!site->enabled || !site->ssl_enabled) {
            continue;
        }
        char cert_path[PATH_MAX];
        char key_path[PATH_MAX];
        if (ensure_auto_certificate(site, cert_path, sizeof(cert_path), key_path, sizeof(key_path), logger) < 0) {
            SSL_CTX_free(ctx);
            return NULL;
        }
        if (validate_tls_pair(site, cert_path, key_path, NULL, 0) < 0 ||
            SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            rpsiod_log_error(logger, NULL, "invalid TLS cert/key for site '%s' in %s", site->name, site->ssl_storage);
            SSL_CTX_free(ctx);
            ERR_clear_error();
            return NULL;
        }
        return ctx;
    }
    SSL_CTX_free(ctx);
    return NULL;
}
