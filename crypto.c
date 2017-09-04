#include "crypto.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

void crypto_perror(const char *msg, int err)
{
	char err_buf[256];

	mbedtls_strerror(err, err_buf, sizeof(err_buf));
	fprintf(stderr, "%s: %s\n", msg, err_buf);
}

const char * crypto_strerror(int err)
{
	static char err_buf[256];

	mbedtls_strerror(err, err_buf, sizeof(err_buf));
	return err_buf;
}

void crypto_init()
{
	const unsigned t_now = time(NULL);

	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
				(const unsigned char *)&t_now, sizeof(t_now));
}

void crypto_deinit()
{
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

int crypto_tls_ctx_new(struct tls_ctx *c, struct identity *id)
{
	int err;

	mbedtls_ssl_init(&c->ssl);
	mbedtls_ssl_config_init(&c->conf);

	err = mbedtls_ssl_config_defaults(&c->conf,
			MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT);
	if (err)
		goto err_out;

	mbedtls_ssl_conf_ca_chain(&c->conf, &id->ca_crt, NULL);
    	mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	if ((err = mbedtls_ssl_conf_own_cert(&c->conf, &id->client_crt, &id->pkey))
    		|| ((err = mbedtls_ssl_setup(&c->ssl, &c->conf))))
		goto err_out;

	return 0;

err_out:
	crypto_perror(__FUNCTION__, err);
	return -1;
}

void crypto_tls_ctx_free(struct tls_ctx *c)
{
	mbedtls_ssl_free(&c->ssl);
	mbedtls_ssl_config_free(&c->conf);
}

int crypto_sign(mbedtls_pk_context pk,
		const unsigned char *data, const unsigned len,
		unsigned char sig[ECCHAT_ECKEY_LEN])
{
	unsigned char hash[32];
	mbedtls_mpi r, s;
	mbedtls_ecp_keypair *signkey = mbedtls_pk_ec(pk);
	int rc;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_sha256(data, len, hash, 0);

	rc = mbedtls_ecdsa_sign(&signkey->grp, &r, &s, &signkey->d,
				hash, sizeof(hash),
				mbedtls_ctr_drbg_random, &ctr_drbg);
	if (rc) {
		crypto_perror(__FUNCTION__, rc);
		goto out;
	}
	mbedtls_mpi_write_binary(&r, sig, ECCHAT_ECP_LEN);
	mbedtls_mpi_write_binary(&s, &sig[ECCHAT_ECP_LEN], ECCHAT_ECP_LEN);
out:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return rc;
}

int crypto_verify_signature(mbedtls_pk_context pk,
			const unsigned char *data, const unsigned len,
			unsigned char sig[ECCHAT_ECKEY_LEN])
{
	unsigned char hash[32];
	mbedtls_mpi r, s;
	mbedtls_ecp_keypair *pubkey = mbedtls_pk_ec(pk);
	int rc;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_mpi_read_binary(&r, sig, ECCHAT_ECP_LEN);
	mbedtls_mpi_read_binary(&s, &sig[ECCHAT_ECP_LEN], ECCHAT_ECP_LEN);

	mbedtls_sha256(data, len, hash, 0);

	rc = mbedtls_ecdsa_verify(&pubkey->grp, hash, sizeof(hash),
				&pubkey->Q, &r, &s);
	if (rc)
		crypto_perror(__FUNCTION__, rc);

	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return rc;
}

int crypto_verify_contact(ecchat_id_t *id,
			mbedtls_x509_crt *contact_crt,
			mbedtls_x509_crt *ca_crt)
{
	unsigned flags = 0;
	int rc;

	rc = mbedtls_x509_crt_verify(contact_crt, ca_crt, NULL,
				ecchat_idstr(id),
				&flags, NULL, NULL);
	if (rc) {
		char b[256];

		mbedtls_strerror(rc, b, sizeof(b) - 1);
		err("%s\n", b);
		mbedtls_x509_crt_verify_info(b, sizeof(b) - 1, "", flags);
		err("%s\n", b);
	}
	return rc;
}

void crypto_key_regenerate(mbedtls_ecp_keypair *key)
{
    	int ret;

	mbedtls_ecp_keypair_free(key);
	mbedtls_ecp_keypair_init(key);
	ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP521R1, key,
				mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret)
		crypto_perror(__FUNCTION__, ret);
}

int crypto_generate_session_key(mbedtls_ecp_keypair *key,
				unsigned char *session_key,
				unsigned char *ecp_x,
				unsigned char *ecp_y)
{
	mbedtls_mpi ecdh_secret;
	mbedtls_ecp_point contact_pubkey;
	unsigned char ecdh_buf[ECCHAT_ECP_LEN];
	int rc;

	mbedtls_mpi_init(&ecdh_secret);
	mbedtls_ecp_point_init(&contact_pubkey);

	mbedtls_mpi_lset(&contact_pubkey.Z, 1);
	mbedtls_mpi_read_binary(&contact_pubkey.X, ecp_x, ECCHAT_ECP_LEN);
	mbedtls_mpi_read_binary(&contact_pubkey.Y, ecp_y, ECCHAT_ECP_LEN);

	rc = mbedtls_ecdh_compute_shared(&key->grp, &ecdh_secret,
					&contact_pubkey, &key->d,
					mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ecp_point_free(&contact_pubkey);
	mbedtls_mpi_write_binary(&ecdh_secret, ecdh_buf, sizeof(ecdh_buf));
	mbedtls_mpi_free(&ecdh_secret);

	if (rc) {
		crypto_perror(__FUNCTION__, rc);
		return rc;
	}
	mbedtls_sha256(ecdh_buf, sizeof(ecdh_buf), session_key, 0);
	hexdump("genkey", session_key, 4);
	return rc;
}

static void crypto_aes(int mode, char *out,
			const char *in, const uint len,
			const uchar *key, const uint keybits,
			uchar iv[ECCHAT_CMSG_IV_LEN])
{
	mbedtls_aes_context ctx;

	mbedtls_aes_init(&ctx);

	if (mode == MBEDTLS_AES_ENCRYPT)
		mbedtls_aes_setkey_enc(&ctx, key, keybits);
	else
		mbedtls_aes_setkey_dec(&ctx, key, keybits);

	mbedtls_aes_crypt_cbc(&ctx, mode, len,
				iv, (uchar *)in, (uchar *)out);
	mbedtls_aes_free(&ctx);
}

void crypto_enc(char *out, const char *in, const uint len, const uchar *key)
{
	uchar iv[ECCHAT_CMSG_IV_LEN];

	mbedtls_ctr_drbg_random(&ctr_drbg, iv, ECCHAT_CMSG_IV_LEN);
	memcpy(out, iv, ECCHAT_CMSG_IV_LEN);

	crypto_aes(MBEDTLS_AES_ENCRYPT, &out[ECCHAT_CMSG_IV_LEN],
			in, len, key, 256, iv);
}

void crypto_dec(char *out, const char *in, const uint len, const uchar *key)
{
	uchar iv[ECCHAT_CMSG_IV_LEN];

	memcpy(iv, in, ECCHAT_CMSG_IV_LEN);
	crypto_aes(MBEDTLS_AES_DECRYPT, out,
		&in[ECCHAT_CMSG_IV_LEN], len,
		key, 256, iv);
}

void crypto_hmac(char *out, const char *in, const uint len, const uchar *key)
{
	int rc;

	rc  = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				key, 32,
				(uchar *)in, len,
				(uchar *)out);
	if (rc)
		crypto_perror(__FUNCTION__, rc);
}
