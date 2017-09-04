#include "ecchat.h"
#include "list.h"
#include "contact.h"
#include "info.h"
#include "client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/fcntl.h>

#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/timing.h>

#define ECCHAT_SERVER_VERSION		1

#define TCP_MAX_CLIENTS 		128
#define KEEPALIVE_CHECK_MSEC 		2000

static struct options {
	u16 port;
} opts = {
	.port = ECCHAT_TCP_PORT_DEF
};

static const char usage[] =
"ecchatd [options]\n"
" --port, -p [port] : TCP listen port\n"
"";

static struct tls_ctx {
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	mbedtls_x509_crt cert;
	mbedtls_pk_context key;
} tls;

static void time_timer_cb(struct uloop_timeout *t);
static void keepalive_timer_cb(struct uloop_timeout *t);
static void reload_contacts_cb(struct uloop_timeout *t);
static void contact_set_online(struct contact *con, int val);


static struct uloop_timeout keepalive_timer = {
	.cb = keepalive_timer_cb
};
static struct uloop_timeout time_timer = {
	.cb = time_timer_cb
};
static struct uloop_timeout reload_contacts = {
	.cb = reload_contacts_cb
};

static struct uloop_fd server_fd;
static struct uloop_fd server_fd6;
static int urandom_fd;
static volatile time_t current_time;
static LIST_HEAD(clients);
struct contacts *contacts;

static void err_mbedtls(int err)
{
	char err_buf[512];

	mbedtls_strerror(err, err_buf, sizeof(err_buf));
	err("%s\n", err_buf);
}

static int client_write_tcp(void *ctx, const unsigned char *buf, size_t len)
{
	struct client *c = (struct client *)ctx;
	ssize_t rc;

	rc = write(c->fd.fd, buf, len);
	if (rc == -1) {
		if (errno == EAGAIN)
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		else
			err_errno("");
	}
	return rc;
}

static int client_read_tcp(void *ctx, unsigned char *buf, size_t len)
{
	struct client *c = (struct client *)ctx;
	ssize_t rc;

	rc = read(c->fd.fd, buf, len);
	if (rc == -1) {
		if (errno == EAGAIN)
			return MBEDTLS_ERR_SSL_WANT_READ;
		else
			err_errno("");
	}
	return rc;
}

static ssize_t client_write_fn(void *ctx, const void *data, size_t len)
{
	struct client *c = (struct client *)ctx;
	int rc;

	rc = mbedtls_ssl_write(&c->ssl, data, len);
	if (rc < 0)
		err_mbedtls(rc);

	return rc;
}

static int client_write(struct client *c, const char *data, size_t len)
{
	int rc;

	if (c->txq.cnt) {
		tx_queue_add(&c->txq, data, len);
		return 0;
	}

	rc = mbedtls_ssl_write(&c->ssl, (const uchar *)data, len);
	if (rc == (int)len) {
		return rc;
	} else if (rc <= 0) {
		if (rc != MBEDTLS_ERR_SSL_WANT_WRITE)
			err_mbedtls(rc);
		tx_queue_add(&c->txq, data, len);
	} else {
		/* partial write */
		tx_queue_add(&c->txq, &data[rc], len - rc);
	}

	if (c->txq.cnt)
		uloop_fd_add(&c->fd, ULOOP_READ | ULOOP_WRITE);

	return rc;
}

static struct client * client_new()
{
	struct client *c = calloc(1, sizeof(*c));

	if (c == NULL)
		return NULL;

	list_add_tail(&c->list, &clients);
	tx_queue_init(&c->txq, 128);
	buffer_init(&c->buf);
	c->sslen = sizeof(c->ss);
	c->fd.fd = -1;
	c->last_seen = current_time;

	mbedtls_ssl_init(&c->ssl);
	mbedtls_ssl_setup(&c->ssl, &tls.conf);
	mbedtls_ssl_set_bio(&c->ssl, c,
			client_write_tcp,
			client_read_tcp, NULL);
	return c;
}

static void client_free(struct client *c)
{
	err("%s\n", ss_ntoa(&c->ss));

	mbedtls_ssl_free(&c->ssl);
	buffer_free(&c->buf);
	tx_queue_deinit(&c->txq);
	uloop_fd_delete(&c->fd);
	if (c->fd.fd != -1)
		close(c->fd.fd);

	/* unlink contact to client ref */
	if (c->contact) {
		c->contact->priv = NULL;
		contact_set_online(c->contact, 0);
	}
	list_del(&c->list);
	free(c);
}

static void client_send_clist(struct client *c)
{
	struct ecchat_clist *cl = &c->contact->clist;
	struct ecchat_hdr *hdr;
	struct ecchat_msg_clist_entry *e;
	unsigned i;
	char *buf;
	const unsigned plen = cl->n_entries * sizeof(*e);
	const unsigned buflen = plen + sizeof(*hdr);

	buf = alloca(buflen);

	hdr = (struct ecchat_hdr *)buf;
	hdr->type = MSG_TYPE_CLIST;
	hdr->version = ECCHAT_SERVER_VERSION;
	hdr->len = plen;

	e = (struct ecchat_msg_clist_entry *)&buf[sizeof(*hdr)];
	for (i = 0; i < cl->n_entries; i++) {
		struct contact *cl_c;

		cl_c = (struct contact *)cl->entries[i].ref;
		e[i].status = cl_c ? cl_c->online : 0;
		e[i].id = cl->entries[i].id;
	}

	ecchat_hdr_to_net_endian(hdr);
	client_write(c, buf, buflen);
}

static void contact_notify_clist(struct contact *c)
{
	struct ecchat_clist *cl = &c->clist;
	unsigned i;

	for (i = 0; i < cl->n_entries; i++) {
		struct ecchat_clist_entry *e = &cl->entries[i];
		struct contact *cl_c = (struct contact *)e->ref;

		if (cl_c->online && cl_c->priv)
			client_send_clist(cl_c->priv);
	}
}

static void contact_set_online(struct contact *con, int val)
{
	con->online = val;
	contact_notify_clist(con);
}

static void client_assign_contact(struct client *c, u8 version,
					const mbedtls_x509_crt *crt)
{
	char buf[256] = {0,0};
	char *cn;
	unsigned cnlen;
	ecchat_id_t id;
	struct contact *contact;

	mbedtls_x509_dn_gets(buf, sizeof(buf) - 1 , &crt->subject);
	cn = strstr(buf, "CN=");
	if (cn == NULL) {
		err("missing CN from peer cert\n");
		return;
	}
	cn += 3;

	cnlen = strlen(cn);
	if (cnlen > ECCHAT_ID_MAXLEN) {
		err("CN exceeds fixed maxlen\n");
		return;
	}
	ecchat_str2id(&id, cn);

	contact = contact_get(contacts, &id);
	if (contact == NULL) {
		err("unknown contact %s\n", cn);
		return;
	}
	if (contact->priv) {
		err("conntact already online: %s\n", cn);
		return;
	}
	contact->latest_client_version = version;
	contact->priv = c;
	c->contact = contact;
}

static struct contact *
contact_lookup_clist(struct contact *c, ecchat_id_t *id)
{
	struct ecchat_clist *cl = &c->clist;
	struct contact *contact = NULL;
	unsigned i;

	for (i = 0; i < cl->n_entries; i++) {
		struct ecchat_clist_entry *e = &cl->entries[i];

		if (!ecchat_id_cmp(&e->id, id)) {
			contact = (struct contact *)e->ref;
			break;
		}
	}

	if (contact) {
		return contact;
	} else {
		char idstr_snd[ECCHAT_ID_MAXLEN + 2];
		char idstr_rcv[ECCHAT_ID_MAXLEN + 2];

		ecchat_id2str(idstr_snd, &c->id);
		ecchat_id2str(idstr_rcv, id);
		err("contact '%s' doesn't know '%s'\n", idstr_snd, idstr_rcv);
		return NULL;
	}
}

static void client_send_ping_ack(struct client *c)
{
	struct ecchat_hdr msg;

	msg.type = MSG_TYPE_PING_ACK;
	msg.version = ECCHAT_SERVER_VERSION;
	msg.len = 0;

	client_write(c, (char *)&msg, sizeof(msg));
}

static void client_fwd_msg(struct client *c)
{
	struct ecchat_hdr *hdr = (struct ecchat_hdr *)c->buf.data;
	struct ecchat_cmsg_msg *m;
	struct contact *c_snd = c->contact;
	struct contact *c_rcv;
	const unsigned plen = ecchat_msglen(hdr);

	if (hdr->len < sizeof(struct ecchat_cmsg_msg) + 1) {
		err("invalid cmsg\n");
		return;
	}

	m = (struct ecchat_cmsg_msg *)(hdr + 1);
	c_rcv = contact_lookup_clist(c_snd, &m->id);
	if (c_rcv == NULL)
		return;

	m->id = c_snd->id;
	ecchat_hdr_to_net_endian(hdr);

	if (c_rcv->priv) {
		struct client *c_dst = c_rcv->priv;

		client_write(c_dst, (char *)hdr, plen);
	} else if (hdr->type == MSG_TYPE_CMSG_MSG) {
		hdr->type = MSG_TYPE_MBOX_MSG;
		contact_mbox_add(c_rcv, (char *)hdr, plen);
	} else {
		err("dropping non msg for offline contact\n");
	}
}

static void client_send_mbox(struct client *c)
{
	struct contact *contact = c->contact;
	unsigned qlen;

	qlen = tx_queue_flush(&contact->mbox, client_write_fn, c);
	if (qlen == 0) {
		uloop_fd_add(&c->fd, ULOOP_READ);
		contact_mbox_del(contact);
	} else {
		uloop_fd_add(&c->fd, ULOOP_READ | ULOOP_WRITE);
		contact_mbox_truncate(contact);
	}
}

static int msg_received(struct client *c)
{
	struct buffer *b = &c->buf;
	struct ecchat_hdr *msg = (struct ecchat_hdr *)buffer_data(b);
	const unsigned len = buffer_len(b);
	unsigned msglen;

	if (len < sizeof(struct ecchat_hdr))
		return -1;

	msglen = ntohs(msg->len) + sizeof(struct ecchat_hdr);
	if (len < msglen)
		/* msg not complete yet */
		return -1;

	ecchat_hdr_to_host_endian(msg);
	ecchat_hdr_print(msg);

	if (c->contact == NULL) {
		client_assign_contact(c, msg->version,
				mbedtls_ssl_get_peer_cert(&c->ssl));
		if (c->contact == NULL)
			return -2;
		contact_set_online(c->contact, 1);
	}

	c->last_seen = current_time;
	nfo("%s ", ecchat_idstr(&c->contact->id));

	switch (msg->type) {
	case MSG_TYPE_CLIST:
		client_send_clist(c);
		break;
	case MSG_TYPE_PING:
		client_send_ping_ack(c);
		break;
	case MSG_TYPE_MBOX:
		client_send_mbox(c);
		break;
	default:
		client_fwd_msg(c);
		break;
	}

	buffer_consume(b, msglen);
	return 0;
}

static void client_cb(struct uloop_fd *fd, unsigned int events)
{
	struct client *c = container_of(fd, struct client, fd);
	int free_client = 0;

	if (fd->error && fd->eof) {
		client_free(c);
		return;
	}

	if (events & ULOOP_WRITE) {
		unsigned qlen;

		qlen = tx_queue_flush(&c->txq, client_write_fn, c);
		if (qlen == 0)
			uloop_fd_add(fd, ULOOP_READ);
	}

	if (events & ULOOP_READ) {
		struct buffer *b = &c->buf;
		ssize_t len;
		int rc;

		for (;;) {
			if (buffer_alloc(b, 1024))
				break;

			len = mbedtls_ssl_read(&c->ssl,
					(uchar *) &b->data[b->wr_pos], 1024);
			if (len == MBEDTLS_ERR_SSL_WANT_READ) {
				break;
        		} else if (len < 0) {
				err_mbedtls(len);
				free_client = 1;
				break;
			} else if (len == 0) {
				nfo("connection closed by peer\n");
				free_client = 1;
				break;
			}
			//err("mbedtls read rc: %zd\n", len);
			b->wr_pos += len;
			while ((rc = msg_received(c)) == 0);
			buffer_flush(b);
			if (rc == -2) {
				free_client = 1;
				break;
			}
		}
		if (free_client)
			client_free(c);
	}
}

static void listen_cb(struct uloop_fd *fd, __unused unsigned int events)
{
	struct client *c = client_new();
	int sfd;

	if (c == NULL)
		return;

	sfd = accept(fd->fd, (struct sockaddr *)&c->ss, &c->sslen);
	if (sfd < 0) {
		err_errno("accept");
		client_free(c);
		return;
	}

	nfo("New connection from %s\n", ss_ntoa(&c->ss));
	c->fd.fd = sfd;
	c->fd.cb = client_cb;
	uloop_fd_add(&c->fd, ULOOP_READ);
}

static int listen_socket(int family)
{
	struct sockaddr_storage ss = {0};
	int sk;
	socklen_t sslen;
	const unsigned ipver = family == AF_INET6 ? 6 : 4;
	int on = 1;

	sk = socket(family, SOCK_STREAM, 0);
	if (sk == -1) {
		err_errno("socket TCP%u", ipver);
		return -1;
	}

	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
		err_errno("socket reuseaddr");
		close(sk);
		return -1;
	}

	ss.ss_family = family;

	if (family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)&ss;

		in->sin_addr.s_addr = INADDR_ANY;
		in->sin_port = htons(opts.port);
		sslen = sizeof(*in);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;

		setsockopt(sk, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

		in6->sin6_addr = in6addr_any;
		in6->sin6_port = htons(opts.port);
		sslen = sizeof(*in6);
	}

	if (bind(sk, (struct sockaddr *)&ss, sslen) == -1) {
		err_errno("bind TCP%u port %hu", ipver, opts.port);
		close(sk);
		return -1;
	}
	if (listen(sk, TCP_MAX_CLIENTS) == -1) {
		err_errno("listen TCP%u", ipver);
		close(sk);
		return -1;
	}
	return sk;
}

static int _urandom(__unused void *ctx, unsigned char *out, size_t len)
{
	if (read(urandom_fd, out, len) < 0)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	return 0;
}

static int tls_init()
{
	int err;

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd == -1) {
		err_errno("open /dev/urandom");
		return -1;
	}

	mbedtls_pk_init(&tls.key);
	mbedtls_x509_crt_init(&tls.cert);
	mbedtls_x509_crt_init(&tls.ca);

	err = mbedtls_ssl_config_defaults(&tls.conf,
			MBEDTLS_SSL_IS_SERVER,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT);

	if ((err = mbedtls_x509_crt_parse_file(&tls.ca, "ca-cert.pem"))
		|| (err = mbedtls_x509_crt_parse_file(&tls.cert, "cert.pem"))
		|| (err = mbedtls_pk_parse_keyfile(&tls.key, "key.pem", NULL)))
		goto err_out;

	mbedtls_ssl_conf_ca_chain(&tls.conf, &tls.ca, NULL);
	mbedtls_ssl_conf_authmode(&tls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_rng(&tls.conf, _urandom, NULL);

	if ((err = mbedtls_ssl_conf_own_cert(&tls.conf, &tls.cert, &tls.key)))
		goto err_out;

	return 0;

err_out:
	err_mbedtls(err);
	return -1;
}

static void tls_deinit()
{
	mbedtls_ssl_config_free(&tls.conf);
	mbedtls_x509_crt_free(&tls.cert);
	mbedtls_x509_crt_free(&tls.ca);
	mbedtls_pk_free(&tls.key);
	close(urandom_fd);
}

static void time_timer_cb(struct uloop_timeout *t)
{
	current_time = time(NULL);
	uloop_timeout_set(t, 1000);
}

static void keepalive_timer_cb(struct uloop_timeout *t)
{
	const time_t tnow = time(NULL);
	struct client *c, *tmp;

	list_for_each_entry_safe(c, tmp, &clients, list) {
		const time_t tdiff = tnow - c->last_seen;

		if (tdiff >= ECCHAT_INACTIVITY_TIMO_SEC)
			client_free(c);
	}
	uloop_timeout_set(t, KEEPALIVE_CHECK_MSEC);
}

static int init_server_fds()
{
	int rc = -1;

	if (tls_init() == -1)
		return -1;

	server_fd.cb = listen_cb;
	server_fd.fd = listen_socket(AF_INET);
	if (server_fd.fd > 0) {
		uloop_fd_add(&server_fd, ULOOP_READ);
		rc++;
	}

	server_fd6.cb = listen_cb;
	server_fd6.fd = listen_socket(AF_INET6);
	if (server_fd6.fd > 0) {
		uloop_fd_add(&server_fd6, ULOOP_READ);
		rc++;
	}

	uloop_timeout_set(&keepalive_timer, KEEPALIVE_CHECK_MSEC);
	uloop_timeout_set(&time_timer, 1000);
	return rc;
}

static void client_contact_update(struct contact *c_new)
{
	struct client *client = c_new->priv;

	if (client)
		client->contact = c_new;
}

static void client_contact_deleted(struct contact *contact)
{
	struct client *client = contact->priv;

	err("%s\n", ecchat_idstr(&contact->id));

	if (client) {
		client->contact = NULL;
		client_free(client);
	}
}

static int init()
{
	contacts_init();
	contacts = contacts_new(client_contact_update,
				client_contact_deleted);

	if (init_server_fds() == -1 || contacts_load(contacts) == -1)
		return -1;

	info_init();
	current_time = time(NULL);
	return 0;
}

static void clients_free()
{
	struct client *c, *tmp;

	list_for_each_entry_safe(c, tmp, &clients, list)
		client_free(c);
}

static void deinit()
{
	clients_free();
	tls_deinit();
	uloop_fd_delete(&server_fd);
	uloop_fd_delete(&server_fd6);
	if (server_fd.fd != -1)
		close(server_fd.fd);
	if (server_fd6.fd != -1)
		close(server_fd6.fd);
	contacts_free(contacts);
	info_deinit();
}

static int parse_args(int argc, char **argv)
{
	static struct option long_options[] = {
		{ "port", required_argument, 0, 'p' },
		{ 0, 0, 0, 0 }
	};
	int option_index = 0;
	int c;

	while ((c = getopt_long(argc, argv, "p:",
				long_options, &option_index)) != -1) {
		switch (c) {
		case 'p':
			opts.port = atoi(optarg);
			break;
		default:
			return -1;
		}
	}
	return 0;
}

static void clients_update_clist()
{
	struct client *c;

	list_for_each_entry(c, &clients, list)
		client_send_clist(c);
}

static void reload_contacts_cb(__unused struct uloop_timeout *t)
{
	struct contacts *c_new = contacts_new(client_contact_update,
						client_contact_deleted);

	if (contacts_load(c_new) == -1) {
		contacts_free(c_new);
		return;
	}
	contacts_move_state(c_new, contacts);
	contacts_free(contacts);
	contacts = c_new;
	clients_update_clist();
}

static void start_reload_contacts(__unused int sig)
{
	uloop_timeout_set(&reload_contacts, 0);
}

int main(int argc, char **argv)
{
	if (parse_args(argc, argv) == -1) {
		puts(usage);
		return -1;
	}

	uloop_init();

	if (init() == -1)
		goto out;

	signal(SIGUSR1, start_reload_contacts);
	uloop_run();

out:
	deinit();
	uloop_done();
	return 0;
}
