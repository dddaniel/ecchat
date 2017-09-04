#ifndef ECCHAT_H
#define ECCHAT_H

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#if defined(_WIN64) || defined(_WIN32)
#include <windows.h>
#else
#include <arpa/inet.h>
#include <alloca.h>
#endif

#include "inttypes.h"

#define ECCHAT_ID_MAXLEN		8
#define ECCHAT_MSG_MAXLEN		1024
#define ECCHAT_ECP_LEN			66
#define ECCHAT_ECKEY_LEN		(ECCHAT_ECP_LEN * 2)
#define ECCHAT_CMSG_BS			16 /* aes-256-cbc block size */
#define ECCHAT_CMSG_IV_LEN		ECCHAT_CMSG_BS
#define ECCHAT_CMSG_HMAC_LEN		32
#define ECCHAT_CMSG_INIT_SIGN_LEN 	(4 * ECCHAT_ECP_LEN)

#define ECCHAT_KEEPALIVE_INTERVAL_SEC	6
#define ECCHAT_INACTIVITY_TIMO_SEC	12

#define ECCHAT_KEEPALIVE_INTERVAL_MSEC	(ECCHAT_KEEPALIVE_INTERVAL_SEC * 1000)
#define ECCHAT_INACTIVITY_TIMO_MSEC	(ECCHAT_INACTIVITY_TIMO_SEC * 1000)

#define ECCHAT_TCP_PORT_DEF		9542

#define __packed __attribute__((packed))
#define __unused __attribute__((unused))

#if defined(_WIN64) || defined(_WIN32)
#define err(fmt, args...) \
	do { \
		fprintf(stderr, "%s: " fmt, __FUNCTION__, ##args); \
		fflush(stderr); \
	} while (0)

#define nfo(fmt, args...) \
	do { \
		printf("%s: " fmt, __FUNCTION__, ##args); \
		fflush(stdout); \
	} while (0)

#else /* not windows */

#define err(fmt, args...) \
	fprintf(stderr, "%s: " fmt, __FUNCTION__, ##args)

#define nfo(fmt, args...) \
	printf("%s: " fmt, __FUNCTION__, ##args)
#endif

#define err_errno(fmt, args...) \
	err(fmt ": %s\n", ##args, strerror(errno))

enum ecchat_hdr_type {
	MSG_TYPE_CLIST,
	MSG_TYPE_PING,
	MSG_TYPE_PING_ACK,
	MSG_TYPE_MBOX,
	MSG_TYPE_MBOX_MSG,
	MSG_TYPE_CMSG_REQUEST,
	MSG_TYPE_CMSG_RESPONSE,
	MSG_TYPE_CMSG_MSG,
	MSG_TYPE_CMSG_ACK,
	__MSG_TYPE_MAX
};

static const char *ecchat_hdr_type_names[] = {
	"clist",
	"ping",
	"ping ack",
	"mbox",
	"mbox msg",
	"cmsg request",
	"cmsg response",
	"cmsg msg",
	"cmsg ack",
};

typedef struct {
	char id[ECCHAT_ID_MAXLEN];
} ecchat_id_t;

struct ecchat_hdr {
	u8 type;
	u8 version;
	u16 len;
} __packed;

struct ecchat_cmsg_ack {
	ecchat_id_t id;
	u16 msgid;
} __packed;

struct ecchat_cmsg_msg {
	ecchat_id_t id;
} __packed;

struct ecchat_cmsg_init {
	ecchat_id_t id;
	unsigned char pubkey_x[ECCHAT_ECP_LEN];
	unsigned char pubkey_y[ECCHAT_ECP_LEN];
	unsigned char offline_pubkey_x[ECCHAT_ECP_LEN];
	unsigned char offline_pubkey_y[ECCHAT_ECP_LEN];
	unsigned char sig[ECCHAT_ECKEY_LEN];
	/* + contact cert of the signer in DER ASN1 format */
} __packed;

/* header in encrypted message from eechat_cmsg_msg
 */
struct ecchat_msghdr {
	u16 len;
	u16 id;
} __packed;

struct ecchat_msg_clist_entry {
	ecchat_id_t id;
	u16 status;
} __packed;

struct ecchat_msg_ack {
	struct ecchat_hdr hdr;
	struct ecchat_cmsg_ack ack;
} __packed;

struct ecchat_clist_entry {
	ecchat_id_t id;
	void *ref;
};

struct ecchat_clist {
	struct ecchat_clist_entry *entries;
	unsigned n_entries;
};

static inline unsigned ecchat_msglen(struct ecchat_hdr *hdr)
{
	return hdr->len + sizeof(*hdr);
}

static inline int ecchat_id_cmp(const ecchat_id_t *id1, const ecchat_id_t *id2)
{
	/* return memcmp(id1, id2, sizeof(ecchat_id_t)); */
	const long long *i1 = (long long *)id1;
	const long long *i2 = (long long *)id2;

	if (*i1 > *i2)
		return 1;
	else if (*i1 < *i2)
		return -1;
	return 0;
}

static inline void ecchat_id2str(char *dst, const ecchat_id_t *src)
{
	unsigned i;

	for (i = 0; i < ECCHAT_ID_MAXLEN && src->id[i] != 0; i++)
		dst[i] = src->id[i];
	dst[i] = 0;
}

static inline void ecchat_str2id(ecchat_id_t *dst, const char *src)
{
	memset(dst, 0, sizeof(ecchat_id_t));
	strncpy(dst->id, src, sizeof(dst->id));
}

static const char * ecchat_hdr_type_str(u16 type)
{
	if (type >= __MSG_TYPE_MAX)
		return "unknown";

	return ecchat_hdr_type_names[type];
}

static inline int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

static inline int hex2bin(char *dst, const char *src, size_t count)
{
	while (count--) {
		int hi = hex_to_bin(*src++);
		int lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}

static inline void bin_to_str(char *dst, const char *src, uint len)
{
	uint pos;
	uint i;

	for (i = pos = 0; i < len; i++)
		pos += sprintf(&dst[pos], "%02x", (unsigned char)src[i]);
}

static inline void hexdump(const char *prefix,
				const unsigned char *src,
				const unsigned len)
{
	char *b = (char *)alloca((len * 2) + 4);

	bin_to_str(b, (char *)src, len);
	printf("%s: %s\n", prefix, b);
}

static inline const char * ecchat_idstr(const ecchat_id_t *id)
{
	static char idstr[ECCHAT_ID_MAXLEN + 2];

	ecchat_id2str(idstr, id);
	return idstr;
}

static inline void ecchat_clist_print(struct ecchat_clist *cl)
{
	unsigned i;

	for (i = 0; i < cl->n_entries; i++) {
		struct ecchat_clist_entry *e = &cl->entries[i];
		const char *idstr = ecchat_idstr(&e->id);

		printf("clist[%02u]: %s (%p)\n", i, idstr, e->ref);
	}
}

static inline void ecchat_id_print(const ecchat_id_t *id)
{
	printf("contact: %s\n", ecchat_idstr(id));
}

static inline void ecchat_hdr_print(struct ecchat_hdr *msg)
{
	printf("type=%s version=%hx len=%u\n",
		ecchat_hdr_type_str(msg->type), msg->version, msg->len);
}

static inline void ecchat_hdr_to_host_endian(struct ecchat_hdr *msg)
{
	msg->len = ntohs(msg->len);
}

static inline void ecchat_hdr_to_net_endian(struct ecchat_hdr *msg)
{
	msg->len = htons(msg->len);
}

static inline void ecchat_msghdr_to_net_endian(struct ecchat_msghdr *hdr)
{
	hdr->len = htons(hdr->len);
	hdr->id = htons(hdr->id);
}

static inline void ecchat_msghdr_to_host_endian(struct ecchat_msghdr *hdr)
{
	hdr->len = ntohs(hdr->len);
	hdr->id = ntohs(hdr->id);
}

static inline uint ecchat_pad(uint len, uint padlen)
{
	const uint mask = padlen - 1;
	return ((len + mask) & ~mask);
}

static inline uint ecchat_msg_padded(uint plain_len)
{
	return ecchat_pad(plain_len, ECCHAT_CMSG_BS);
}

static inline uint ecchat_cmsg_len(uint msglen)
{
	return sizeof(struct ecchat_hdr) +
		sizeof(struct ecchat_cmsg_msg) +
		ECCHAT_CMSG_IV_LEN +
		ecchat_msg_padded(msglen) +
		ECCHAT_CMSG_HMAC_LEN;
}

static inline unsigned ecchat_cmsg_init_len(unsigned contact_cert_len)
{
	return sizeof(struct ecchat_hdr) +
		sizeof(struct ecchat_cmsg_init) +
		contact_cert_len;
}

#endif
