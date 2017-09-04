#include "identity.h"
#include "crypto.h"
#include "ecchat.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <mbedtls/sha256.h>

static void identity_init(struct identity *id)
{
	mbedtls_x509_crt_init(&id->client_crt);
	mbedtls_x509_crt_init(&id->ca_crt);
	mbedtls_pk_init(&id->pkey);
}

static void identity_deinit(struct identity *id)
{
	mbedtls_x509_crt_free(&id->client_crt);
	mbedtls_x509_crt_free(&id->ca_crt);
	mbedtls_pk_free(&id->pkey);
}

static int load_crt(mbedtls_x509_crt *crt, const char *dir, const char *name)
{
	char crt_file[PATH_MAX];
	int rc;

	sprintf(crt_file, "%s/%s", dir, name);
    	rc = mbedtls_x509_crt_parse_file(crt, crt_file);
	if (rc)
		err("%s: %s\n", crt_file, crypto_strerror(rc));
	return rc;
}

static int validate_encrypted_key_file(const char *file)
{
	struct stat sb;

	if (stat(file, &sb) == -1) {
		err_errno("stat %s", file);
		return -1;
	}
	if (sb.st_size < (ECCHAT_CMSG_IV_LEN + ECCHAT_ECP_LEN))
		return -1;
	if (sb.st_size % ECCHAT_CMSG_BS)
		return -1;

	return 0;
}

static enum identity_rc load_private_key(mbedtls_pk_context *pk, const char *dir)
{
	char key_file[PATH_MAX];
	int rc;

	/* try encrypted first, fallback to key.pem
	 */
	sprintf(key_file, "%s/key.enc", dir);
	if (validate_encrypted_key_file(key_file) == -1) {
		sprintf(key_file, "%s/key.pem", dir);
		rc = mbedtls_pk_parse_keyfile(pk, key_file, NULL);
		if (rc) {
			err("%s: %s\n", key_file, crypto_strerror(rc));
			return IDENTITY_LOAD_FAILED;
		} else {
			return IDENTITY_LOAD_OK;
		}
	} else {
		return IDENTITY_LOAD_REQ_PWD;
	}
}

enum identity_rc identity_load(struct identity *id, const char *dir)
{
	int rc;

	identity_init(id);
	rc = load_crt(&id->client_crt, dir, "cert.pem");
	rc |= load_crt(&id->ca_crt, dir, "ca-cert.pem");

	if (rc)
		return IDENTITY_LOAD_FAILED;

	return load_private_key(&id->pkey, dir);
}

void identity_unload(struct identity *id)
{
	identity_deinit(id);
}

static ssize_t load_file(const char *file, char *buf, const unsigned len)
{
	ssize_t rc;
	int fd;

#if defined(_WIN64) || defined(_WIN32)
	fd = open(file, O_RDONLY | O_BINARY);
#else
	fd = open(file, O_RDONLY);
#endif
	if (fd == -1) {
		err_errno("open %s", file);
		return -1;
	}

	rc = read(fd, buf, len);
	if (rc == -1)
		err_errno("read %s", file);
	close(fd);
	return rc;
}

static int ec_privkey_to_pk(mbedtls_pk_context *pk, const char *privkey)
{
	mbedtls_ecp_keypair *k = malloc(sizeof(*k));

	if (k == NULL)
		return -1;

	mbedtls_ecp_keypair_init(k);
	mbedtls_ecp_group_load(&k->grp, MBEDTLS_ECP_DP_SECP521R1);
	mbedtls_mpi_read_binary(&k->d, (uchar *)privkey, ECCHAT_ECP_LEN);

	pk->pk_ctx = k;
	pk->pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
	return 0;
}

int identity_decrypt_private_key(struct identity *id,
				const char *dir,
				const char *pwd,
				const unsigned len)
{
	char key_file[PATH_MAX];
	char key_enc[128];
	char key_dec[128];
	unsigned char sha_pwd[32];
	mbedtls_ecp_keypair *kp;
	ssize_t klen;
	int rc;

	sprintf(key_file, "%s/key.enc", dir);
	klen = load_file(key_file, key_enc, sizeof(key_enc));
	if (klen == -1)
		return -1;

	mbedtls_sha256((uchar *)pwd, len, sha_pwd, 0);
	crypto_dec(key_dec, key_enc, klen - ECCHAT_CMSG_IV_LEN, sha_pwd);

	if (ec_privkey_to_pk(&id->pkey, key_dec) == -1)
		return -1;

	kp = mbedtls_pk_ec(id->pkey);
	rc = mbedtls_ecp_check_privkey(&kp->grp, &kp->d);
	if (rc) {
		mbedtls_pk_free(&id->pkey);
		err("%s\n", crypto_strerror(rc));
	}

	return rc;
}
