#ifndef CLIENT_H
#define CLIENT_H

#include "contact.h"
#include "txqueue.h"
#include "buffer.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <mbedtls/ssl.h>
#include <libubox/uloop.h>

struct client {
	mbedtls_ssl_context ssl;
	struct uloop_fd fd;

	struct contact *contact;
	struct buffer buf;
	struct tx_queue txq;

	struct sockaddr_storage ss;
	socklen_t sslen;

	time_t last_seen;
	struct list_head list;
};

static inline const char * ss_ntoa(struct sockaddr_storage *ss)
{
	static char addr[INET6_ADDRSTRLEN + 8];
	u16 port;

	if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *in = (struct sockaddr_in *)ss;
		inet_ntop(AF_INET, &in->sin_addr, addr, INET_ADDRSTRLEN);
		port = ntohs(in->sin_port);
	} else {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss;
		inet_ntop(AF_INET6, &in6->sin6_addr, addr, INET6_ADDRSTRLEN);
		port = ntohs(in6->sin6_port);
	}
	sprintf(&addr[strlen(addr)], ":%hu", port);
	return addr;
}

#endif
