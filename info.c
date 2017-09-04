#include "info.h"
#include "contact.h"
#include "client.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#define UNIX_PATH "/tmp/ecchatd.socket"

extern struct contacts *contacts;

static char * gen_info()
{
	struct blob_buf b = {0};
	struct contact *c;
	char *str;

	blob_buf_init(&b, 0);
	avl_for_each_element(&contacts->tree, c, node) {
		void *t = blobmsg_open_table(&b, ecchat_idstr(&c->id));
		struct client *client = c->priv;

		blobmsg_add_u32(&b, "mbox", c->mbox.cnt);
		blobmsg_add_u32(&b, "version", c->latest_client_version);

		if (client) {
			blobmsg_add_string(&b, "remote", ss_ntoa(&client->ss));
			blobmsg_add_u32(&b, "txq", client->txq.cnt);
		}
		blobmsg_close_table(&b, t);
	}
	str = blobmsg_format_json_indent(b.head, true, 0);
	blob_buf_free(&b);
	return str;
}

static void unix_fd_cb(struct uloop_fd *fd, unsigned events)
{
	struct sockaddr_un un;
	socklen_t slen = sizeof(un);
	char buf[32];
	char *info_str;
	ssize_t rc;

	if (!(events & ULOOP_READ))
		return;

	rc = recvfrom(fd->fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&un, &slen);
	if (rc == -1)
		err_errno("read");

	info_str = gen_info();
	if (info_str) {
		rc = sendto(fd->fd, info_str, strlen(info_str), 0,
				(struct sockaddr *)&un, slen);
		if (rc == -1)
			err_errno("write");
		free(info_str);
	}
}

static struct uloop_fd unix_fd = {
	.fd = -1,
	.cb = unix_fd_cb
};

void info_init()
{
	struct sockaddr_un un = {0};
	int sk;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk == -1) {
		err_errno("socket");
		return;
	}
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, UNIX_PATH);

	unlink(UNIX_PATH);
	if (bind(sk, (struct sockaddr *)&un, sizeof(un)) == -1) {
		err_errno("bind %s", UNIX_PATH);
		close(sk);
		return;
	}
	unix_fd.fd = sk;
	uloop_fd_add(&unix_fd, ULOOP_READ);
}

void info_deinit()
{
	if (unix_fd.fd != -1) {
		uloop_fd_delete(&unix_fd);
		close(unix_fd.fd);
		unlink(UNIX_PATH);
	}
}
