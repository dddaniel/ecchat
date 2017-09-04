#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/timing.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>

#include "inttypes.h"
#include "ecchat.h"
#include "identity.h"

struct tls_ctx {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
};

void crypto_init();
void crypto_deinit();
int crypto_tls_ctx_new(struct tls_ctx *c, struct identity *id);
void crypto_tls_ctx_free(struct tls_ctx *c);
void crypto_perror(const char *msg, int err);
const char * crypto_strerror(int err);
void crypto_key_regenerate(mbedtls_ecp_keypair *key);
int crypto_generate_session_key(mbedtls_ecp_keypair *key,
				unsigned char *session_key,
				unsigned char *ecp_x,
				unsigned char *ecp_y);
void crypto_enc(char *out, const char *in, const uint len, const uchar *key);
void crypto_dec(char *out, const char *in, const uint len, const uchar *key);
void crypto_hmac(char *out, const char *in, const uint len, const uchar *key);
int crypto_sign(mbedtls_pk_context pk,
		const unsigned char *data,
		const unsigned len,
		unsigned char sig[ECCHAT_ECKEY_LEN]);
int crypto_verify_signature(mbedtls_pk_context pk,
			const unsigned char *data,
			const unsigned len,
			unsigned char sig[ECCHAT_ECKEY_LEN]);
int crypto_verify_contact(ecchat_id_t *id,
			mbedtls_x509_crt *contact_crt,
			mbedtls_x509_crt *ca_crt);

#ifdef __cplusplus
}
#endif

#endif
