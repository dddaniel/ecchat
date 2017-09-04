#ifndef IDENTITY_H
#define IDENTITY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mbedtls/certs.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>

struct identity {
	mbedtls_x509_crt client_crt;
	mbedtls_x509_crt ca_crt;
	mbedtls_pk_context pkey;
};

enum identity_rc {
	IDENTITY_LOAD_OK,
	IDENTITY_LOAD_FAILED,
	IDENTITY_LOAD_REQ_PWD
};

enum identity_rc identity_load(struct identity *id, const char *dir);
void identity_unload(struct identity *id);
int identity_decrypt_private_key(struct identity *id,
				const char *dir,
				const char *pwd,
				const unsigned len);

#ifdef __cplusplus
}
#endif

#endif
