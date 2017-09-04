#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/sha256.h>

#include "crypto.h"

static const char usage[] =
"ecchat-encrypt-id [private-key.pem] [pass]";

static int load_key(unsigned char *dst, const unsigned len, const char *key_file)
{
	mbedtls_pk_context pk;
	mbedtls_ecp_keypair *kp;
	int rc;

	mbedtls_pk_init(&pk);
	rc = mbedtls_pk_parse_keyfile(&pk, key_file, NULL);
	if (rc) {
		err("load key %s\n", crypto_strerror(rc));
		return -1;
	}
	kp = mbedtls_pk_ec(pk);
	mbedtls_mpi_write_binary(&kp->d, dst, len);
	mbedtls_pk_free(&pk);
	return 0;
}

static int test_decrypt(char *key_enc,
			const unsigned len,
			const unsigned char sha_pwd[32])
{
	char key[256];
	mbedtls_mpi d;
	mbedtls_ecp_group grp;
	int rc;

	mbedtls_mpi_init(&d);
	mbedtls_ecp_group_init(&grp);

	crypto_dec(key, key_enc, len, sha_pwd);

	mbedtls_mpi_read_binary(&d, (uchar *)key, ECCHAT_ECP_LEN);
	mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP521R1);
	rc = mbedtls_ecp_check_privkey(&grp, &d);
	if (rc)
		err("%s\n", crypto_strerror(rc));

	mbedtls_ecp_group_free(&grp);
	mbedtls_mpi_free(&d);
	return rc;
}

int main(int argc, char **argv)
{
	unsigned char key[ECCHAT_ECP_LEN];
	unsigned char sha_pwd[32];
	char *key_padded;
	char *key_enc;
	const char *key_file;
	const unsigned char *pwd;
	const unsigned len_padded = ecchat_msg_padded(ECCHAT_ECP_LEN);
 	const u8 pad_byte = len_padded - ECCHAT_ECP_LEN;

	if (argc != 3) {
		puts(usage);
		return -1;
	}
	key_file = argv[1];
	pwd = (unsigned char *)argv[2];

	if (load_key(key, sizeof(key), key_file) == -1)
		return -1;

	key_padded = alloca(len_padded);
	memcpy(key_padded, key, sizeof(key));
	memset(&key_padded[sizeof(key)], pad_byte, pad_byte);

	mbedtls_sha256(pwd, strlen((char *)pwd), sha_pwd, 0);
	key_enc = alloca(len_padded + ECCHAT_CMSG_IV_LEN);
	crypto_init();
	crypto_enc(key_enc, key_padded, len_padded, sha_pwd);

	if (!test_decrypt(key_enc, len_padded, sha_pwd))
		write(STDOUT_FILENO, key_enc, len_padded + ECCHAT_CMSG_IV_LEN);

	crypto_deinit();
	return 0;
}
