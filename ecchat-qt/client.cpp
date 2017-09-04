#include "client.hpp"
#include "mainwindow.hpp"
#include "contact.h"
#include "ecchat-qt.h"
#include "version.h"

#include "../identity.h"
#include "../list.h"

#if defined(_WIN64) || defined(_WIN32)
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#endif

#include <unistd.h>
#include <mbedtls/bignum.h>
#include <string.h>

#include <QDebug>

#define ERR_MSG_MAXLEN "Message exceeds maxlen"

#define ECCHAT_CMSG_MSG_MINLEN \
	(sizeof(struct ecchat_cmsg_msg) + \
	ECCHAT_CMSG_IV_LEN + \
	ECCHAT_CMSG_BS + \
	ECCHAT_CMSG_HMAC_LEN)

struct ecchat_p_msg {
	struct ecchat_hdr *hdr;
	struct ecchat_cmsg_msg *cmsg;
	char *iv;
	char *msg;
	char *hmac;
	unsigned msglen;
};

extern MainWindow *m;
extern struct options opts;
extern struct identity identity;

static const char * state_names[] = {
	"disconnected",
	"connecting",
	"ssl init",
	"ssl connected"
};

static inline void dbg_phex(char *bin, unsigned len)
{
	char str[(len * 2) + 2];

	bin_to_str(str, bin, len);
	err("%s\n", str);
}

Client_notifier ::
Client_notifier(qintptr sk, QSocketNotifier::Type t, Client *p)
	: QSocketNotifier(sk, t), parent(p)
{
	connect(this, &QSocketNotifier::activated,
	        this, &Client_notifier::on_activated);
}

Client_notifier :: ~Client_notifier()
{
	disconnect(this, &QSocketNotifier::activated,
	        this, &Client_notifier::on_activated);
}

static int ecchat_parse_cmsg_msg(struct ecchat_p_msg *msg, char *buf)
{
	struct ecchat_hdr *hdr = (struct ecchat_hdr *)buf;
	unsigned hmac_off;

	memset(msg, 0, sizeof(*msg));

	if (hdr->len < ECCHAT_CMSG_MSG_MINLEN) {
		err("msg to small %hu\n", hdr->len);
		return -1;
	}
	msg->hdr = hdr;
	msg->cmsg = (struct ecchat_cmsg_msg *)(hdr + 1);
	msg->iv = (char *)(msg->cmsg + 1);
	msg->msg = msg->iv + ECCHAT_CMSG_IV_LEN;
	hmac_off = (sizeof(*hdr) + hdr->len) - ECCHAT_CMSG_HMAC_LEN;
	msg->hmac = &buf[hmac_off];
	msg->msglen = msg->hmac - msg->msg;

	if (msg->msglen > ECCHAT_MSG_MAXLEN) {
		err("msg exceeds maxlen\n");
		return -1;
	}
	return 0;
}

static int client_write_tcp(void *ctx, const unsigned char *buf, size_t len)
{
	Client *c = (Client *)ctx;
	ssize_t rc;

	rc = c->os_write(c->sk, buf, len);
	if (rc == -1) {
		c->sk_error("os wirte");
		c->reconnect();
	}
	return rc;
}

static int client_read_tcp(void *ctx, unsigned char *buf, size_t len)
{
	Client *c = (Client *)ctx;
	ssize_t rc;

	rc = c->os_read(c->sk, buf, len);
	if (rc == -1) {
		c->sk_error("os read");
		c->reconnect();
	}
	return rc;
}

Client :: Client()
	: sk(-1), notif_rd(NULL), notif_wr(NULL), state(STATE_DISCONNECTED)
{
	memset(&tls, 0, sizeof(tls));
	buffer_init(&buf);

	connect(&msg_timeout_timer, &QTimer::timeout,
	        this, &Client::msg_timeout_timer_cb);
	connect(&keepalive_timer, &QTimer::timeout,
	        this, &Client::keepalive_timer_cb);
	connect(&reconnect_timer, &QTimer::timeout,
	        this, &Client::reconnect_timer_cb);
	connect(&connect_timer, &QTimer::timeout,
	        this, &Client::connect_timer_cb);

	reconnect_timer.setSingleShot(true);
	connect_timer.setSingleShot(true);
	msg_timeout_timer.setSingleShot(true);
}

Client :: ~Client()
{
	stop();
	crypto_tls_ctx_free(&tls);
	buffer_free(&buf);
}

int Client :: _start()
{
	struct sockaddr_in sa;
	int rc;

	sk = ::socket(AF_INET, SOCK_STREAM, 0);
	if (sk == -1) {
		sk_error("socket");
		return -1;
	}
	set_nonblock();

	sa.sin_family = AF_INET;
	sa.sin_port = htons(opts.port);
	sa.sin_addr.s_addr = inet_addr(opts.server);

	rc = os_connect(sk, (struct sockaddr *)&sa, sizeof(sa));
	if (rc == -1) {
		sk_error("connect");
		os_close(sk);
		sk = -1;
		return -1;
	}

	if (notif_rd)
		delete notif_rd;
	if (notif_wr)
		delete notif_wr;

	notif_rd = new Client_notifier(sk, QSocketNotifier::Read, this);
	notif_wr = new Client_notifier(sk, QSocketNotifier::Write, this);
	if (!notif_rd || !notif_wr) {
		err("out of memory\n");
		return -1;
	}
	notif_rd->setEnabled(true);
	notif_wr->setEnabled(true);

	return 0;
}

void Client :: start()
{
	set_state(STATE_CONNECTING);

	if (_start() == -1)
		reconnect_timer.start(RECONNECT_INT_MSEC);
	else
		connect_timer.start(CONNECT_TIMO_MSEC);
}

void Client :: stop()
{
	keepalive_timer.stop();
	contacts_set_offline();

	notif_rd->setEnabled(false);
	notif_wr->setEnabled(false);

	if (state != STATE_DISCONNECTED)
		mbedtls_ssl_session_reset(&tls.ssl);

	if (sk != -1) {
		os_close(sk);
		sk = -1;
	}
	set_state(STATE_DISCONNECTED);
}

void Client :: send_cmsg_request(struct contact *c)
{
	if (c->session_init == false) {
		if (send_cmsg_req_res(c, true) > 0)
			c->session_init = true;
	}
}

void Client :: send_cmsg_response(struct contact *c)
{
	send_cmsg_req_res(c, false);
}

int Client :: send_cmsg_req_res(struct contact *c, bool is_req)
{
	const unsigned char *crt = identity.client_crt.raw.p;
	const unsigned crt_len = identity.client_crt.raw.len;
	char buf[ecchat_cmsg_init_len(crt_len)];
	struct ecchat_hdr *hdr = (struct ecchat_hdr *)buf;
	struct ecchat_cmsg_init *i = (struct ecchat_cmsg_init *)(hdr + 1);
	char *cert_off = (char *)(i + 1);

	if (is_req)
		hdr->type = MSG_TYPE_CMSG_REQUEST;
	else
		hdr->type = MSG_TYPE_CMSG_RESPONSE;

	hdr->version = ECCHAT_CLIENT_VERSION;
	hdr->len = sizeof(buf) - sizeof(*hdr);
	i->id = c->id;

	if (is_req) {
		crypto_key_regenerate(&c->key);
		crypto_key_regenerate(&c->key_offline);
	}

	mbedtls_mpi_write_binary(&c->key.Q.X, i->pubkey_x, sizeof(i->pubkey_x));
	mbedtls_mpi_write_binary(&c->key.Q.Y, i->pubkey_y, sizeof(i->pubkey_y));
	mbedtls_mpi_write_binary(&c->key_offline.Q.X, i->offline_pubkey_x,
				sizeof(i->offline_pubkey_x));
	mbedtls_mpi_write_binary(&c->key_offline.Q.Y, i->offline_pubkey_y,
				sizeof(i->offline_pubkey_y));

	crypto_sign(identity.pkey, i->pubkey_x, ECCHAT_CMSG_INIT_SIGN_LEN, i->sig);
	memcpy(cert_off, crt, crt_len);

	ecchat_hdr_to_net_endian(hdr);
	return send(buf, sizeof(buf));
}

int Client :: send_cmsg_msg(struct contact *c,
				const u16 id,
                         	const char *msg,
                         	const unsigned len)
{
	const unsigned msglen = len + sizeof(struct ecchat_msghdr);
	const unsigned buflen = ecchat_cmsg_len(msglen);
	const unsigned len_padded = ecchat_msg_padded(msglen);
	const unsigned char *key;
	struct ecchat_hdr *hdr;
	struct ecchat_cmsg_msg *cmsg;
	struct ecchat_msghdr *msghdr;
	char *msg_padded;
	char *buf;
	char *payload;
	char *hmac;
 	const u8 pad_byte = len_padded - msglen;

	if (msglen > ECCHAT_MSG_MAXLEN) {
		err("%s\n", ERR_MSG_MAXLEN);
		contact_add_message(c, ERR_MSG_MAXLEN, 1, 1);
		return -2;
	}

	if (c->online) {
		if (c->session_estab == false) {
			err("session not established, sending req\n");
			send_cmsg_request(c);
			return -1;
		}
		key = c->session_key;
	} else {
		key = c->offline_key;
	}

	msg_padded = (char *)alloca(len_padded);

	msghdr = (struct ecchat_msghdr *)msg_padded;
	msghdr->len = htons(len);
	msghdr->id = htons(id);

	memcpy(&msg_padded[sizeof(*msghdr)], msg, len);
	msg_padded[msglen] = 0;
	memset(&msg_padded[msglen], pad_byte, pad_byte);

	buf = (char *)alloca(buflen);

	hdr = (struct ecchat_hdr *)buf;
	hdr->type = MSG_TYPE_CMSG_MSG;
	hdr->version = ECCHAT_CLIENT_VERSION;
	hdr->len = buflen - sizeof(*hdr);

	cmsg = (struct ecchat_cmsg_msg *)(hdr + 1);
	cmsg->id = c->id;

	payload = (char *)(cmsg + 1);
	crypto_enc(payload, msg_padded, len_padded, key);
	hmac = payload + ECCHAT_CMSG_IV_LEN + len_padded;
	crypto_hmac(hmac, msg_padded, len_padded, key);

	ecchat_hdr_to_net_endian(hdr);
	return send(buf, buflen);
}

void Client :: rcv_cmsg_msg(char *buf, bool offline_msg)
{
	char txt[ECCHAT_MSG_MAXLEN + 32];
	char hmac[ECCHAT_CMSG_HMAC_LEN];
	struct ecchat_p_msg msg;
	struct ecchat_msghdr *msghdr;
	struct contact *contact;
	const unsigned char *key;

	if (ecchat_parse_cmsg_msg(&msg, buf) == -1)
		return;

	contact = contact_get(&msg.cmsg->id);
	if (contact == NULL)
		return;

	if (offline_msg) {
		key = contact->offline_key;
	} else {
		if (!contact->session_estab) {
			err("session not established\n");
			send_cmsg_request(contact);
			return;
		}
		key = contact->session_key;
	}

	crypto_dec(txt, msg.iv, msg.msglen, key);
	crypto_hmac(hmac, txt, msg.msglen, key);

	if (memcmp(hmac, msg.hmac, sizeof(hmac))) {
		err("hmac verify failed\n");
		if (!offline_msg)
			send_cmsg_request(contact);
		return;
	}

	msghdr = (struct ecchat_msghdr *)txt;
	ecchat_msghdr_to_host_endian(msghdr);
	err("len %hu id %hu\n", msghdr->len, msghdr->id);
	send_cmsg_ack(contact, msghdr->id);

	//err("len=%zu msg=%s\n", strlen(&txt[sizeof(*msghdr)]), &txt[sizeof(*msghdr)]);
	contact_add_message(contact, &txt[sizeof(*msghdr)], 0, 0);
}

void Client :: rcv_cmsg_ack(char *buf)
{
	struct ecchat_hdr *hdr = (struct ecchat_hdr *)buf;
	struct ecchat_cmsg_ack *ack;
	struct contact *contact;

	if (hdr->len != sizeof(struct ecchat_cmsg_ack)) {
		err("invalid cmsg ack received\n");
		return;
	}

	ack = (struct ecchat_cmsg_ack *)(hdr + 1);
	contact = contact_get(&ack->id);
	if (contact)
		contact_ack_message(contact, ntohs(ack->msgid));
}

void Client :: rcv_clist(char *buf)
{
	struct ecchat_hdr *msg = (struct ecchat_hdr *)buf;
	struct ecchat_msg_clist_entry *e;
	const unsigned n_entries = msg->len / sizeof(*e);

	e = (struct ecchat_msg_clist_entry *)(msg + 1);
	contacts_update(e, n_entries);
}

#define ECCHAT_CRT_MINLEN 128

void Client :: rcv_cmsg_request(char *buf)
{
	rcv_cmsg_req_res(buf, true);
}

void Client :: rcv_cmsg_response(char *buf)
{
	rcv_cmsg_req_res(buf, false);
}

void Client :: rcv_cmsg_req_res(char *buf, bool is_req)
{
	struct ecchat_hdr *hdr = (struct ecchat_hdr *)buf;
	struct ecchat_cmsg_init *i = (struct ecchat_cmsg_init *)(hdr + 1);
	const unsigned char *crt_der = (unsigned char *)(i + 1);
	struct contact *contact;
	const unsigned crt_der_len = hdr->len - sizeof(*i);
	mbedtls_x509_crt crt;
	int rc;

	if (hdr->len < sizeof(*i) + ECCHAT_CRT_MINLEN) {
		err("msg to small\n");
		return;
	}

	contact = contact_get(&i->id);
	if (contact == NULL)
		return;

	mbedtls_x509_crt_init(&crt);
	rc = mbedtls_x509_crt_parse_der(&crt, crt_der, crt_der_len);
	if (rc) {
		crypto_perror(__FUNCTION__, rc);
		mbedtls_x509_crt_free(&crt);
		return;
	}

	if (is_req) {
		crypto_key_regenerate(&contact->key);
		crypto_key_regenerate(&contact->key_offline);
	}

	rc = crypto_verify_contact(&i->id, &crt, &identity.ca_crt);
	rc |= crypto_verify_signature(crt.pk,
					i->pubkey_x,
					ECCHAT_CMSG_INIT_SIGN_LEN,
					i->sig);
	mbedtls_x509_crt_free(&crt);

	rc |= crypto_generate_session_key(&contact->key,
					contact->session_key,
					i->pubkey_x, i->pubkey_y);
	rc |= crypto_generate_session_key(&contact->key_offline,
					contact->offline_key,
					i->offline_pubkey_x,
					i->offline_pubkey_y);

	if (!rc) {
		if (is_req)
			send_cmsg_response(contact);
		contact_session_established(contact);
	} else {
		contact_session_clear(contact);
	}
}

void Client :: msg_received()
{
	msg_timeout_timer.start(ECCHAT_INACTIVITY_TIMO_MSEC);
}

int Client :: input(char *buf, unsigned len)
{
	struct ecchat_hdr *msg = (struct ecchat_hdr *)buf;

	if (len < sizeof(struct ecchat_hdr)) {
		return -1;
	}

	if (len < ntohs(msg->len) + sizeof(struct ecchat_hdr)) {
		/* msg not complete yet */
		return -1;
	}

	ecchat_hdr_to_host_endian(msg);
	ecchat_hdr_print(msg);
	msg_received();

	switch (msg->type) {
	case MSG_TYPE_CLIST:
		rcv_clist(buf);
		break;
	case MSG_TYPE_MBOX_MSG:
		rcv_cmsg_msg(buf, true);
		break;
	case MSG_TYPE_CMSG_REQUEST:
		rcv_cmsg_request(buf);
		break;
	case MSG_TYPE_CMSG_RESPONSE:
		rcv_cmsg_response(buf);
		break;
	case MSG_TYPE_CMSG_MSG:
		rcv_cmsg_msg(buf);
		break;
	case MSG_TYPE_CMSG_ACK:
		rcv_cmsg_ack(buf);
		break;
	default:
		break;
	}
	buffer_consume(&this->buf, ecchat_msglen(msg));
	return 0;
}

void Client :: reconnect(bool delayed)
{
	stop();

	if (delayed)
		reconnect_timer.start(RECONNECT_INT_MSEC);
	else
		start();
}

void Client :: connect_timer_cb()
{
	if (state != STATE_SSL_CONNECTED)
		reconnect();
}

void Client :: reconnect_timer_cb()
{
	start();
}

void Client :: msg_timeout_timer_cb()
{
	err("server timed out\n");
	reconnect(false);
}

void Client :: keepalive_timer_cb()
{
	if (state == STATE_SSL_CONNECTED)
		send_server_msg(MSG_TYPE_PING);
}

int Client :: init()
{
	if (os_init() == -1)
		return -1;

	if (crypto_tls_ctx_new(&tls, &identity) == -1)
		return -1;

	mbedtls_ssl_set_bio(&tls.ssl, this,
	                    client_write_tcp,
	                    client_read_tcp, NULL);
	return 0;
}

int Client :: send(const char *msg, size_t len)
{
	int rc = mbedtls_ssl_write(&tls.ssl, (const uchar *)msg, len);

	if (rc < 0)
		crypto_perror(__FUNCTION__, rc);

	return rc;
}

void Client :: send_server_msg(enum ecchat_hdr_type t)
{
	struct ecchat_hdr msg = {
		.type = t,
		.version = ECCHAT_CLIENT_VERSION,
		.len = 0
	};
	send((char *)&msg, sizeof(msg));
}

void Client :: send_cmsg_ack(struct contact *c, u16 id)
{
	struct ecchat_msg_ack ack;

	ack.hdr.type = MSG_TYPE_CMSG_ACK;
	ack.hdr.version = ECCHAT_CLIENT_VERSION;
	ack.hdr.len = sizeof(struct ecchat_cmsg_ack);
	ack.ack.id = c->id;
	ack.ack.msgid = htons(id);

	ecchat_hdr_to_net_endian(&ack.hdr);
	send((char *)&ack, sizeof(ack));
}

void Client :: set_state(enum state s)
{
	this->state = s;
	err("%s\n", state_names[s]);
	m->status_update(state_names[s]);
}

void Client :: do_write()
{
	if (state == STATE_CONNECTING) {
		set_state(STATE_SSL_INIT);
		mbedtls_ssl_handshake(&tls.ssl);
	}
	notif_wr->setEnabled(false);
}

void Client :: connection_ready()
{
	send_server_msg(MSG_TYPE_CLIST);
	send_server_msg(MSG_TYPE_MBOX);
	keepalive_timer.start(ECCHAT_KEEPALIVE_INTERVAL_MSEC);
}

void Client :: check_ssl_state()
{
	const mbedtls_ssl_context *ssl = &tls.ssl;

	if (ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER) {
		int rc = mbedtls_ssl_get_verify_result(ssl);

		if (rc) {
			char b[256];

			mbedtls_x509_crt_verify_info(b, sizeof(b) - 1, "", rc);
			err("%s\n", b);
			reconnect();
		} else {
			set_state(STATE_SSL_CONNECTED);
			connection_ready();
		}
	}
}

void Client :: do_read()
{
	ssize_t len;

	for (;;) {
		if (buffer_alloc(&buf, 1024))
			break;

		len = mbedtls_ssl_read(&tls.ssl,
		                       (uchar *)&buf.data[buf.wr_pos], 1024);
		if (len == MBEDTLS_ERR_SSL_WANT_READ) {
			break;
		} else if (len < 0) {
			crypto_perror(__FUNCTION__, len);
			reconnect();
			break;
		} else if (len == 0) {
			err("Connection closed\n");
			reconnect();
			break;
		}

		buf.wr_pos += len;
		while (input(buffer_data(&buf), buffer_len(&buf)) != -1);
		buffer_flush(&buf);
	}
	if (state == STATE_SSL_INIT)
		check_ssl_state();
}

void Client_notifier :: on_activated(int)
{
	switch (type()) {
	case QSocketNotifier::Write:
		parent->do_write();
		break;
	case QSocketNotifier::Read:
		parent->do_read();
		break;
	default:
		break;
	}
}
