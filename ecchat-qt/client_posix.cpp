#include "client.hpp"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

int Client :: os_init()
{
	return 0;
}

void Client :: set_nonblock()
{
	fcntl(sk, F_SETFL, fcntl(sk, F_GETFL) | O_NONBLOCK);
}

void Client :: sk_error(const char *msg)
{
	err_errno("%s", msg);
}

int Client :: os_connect(int sk, struct sockaddr *sa, unsigned long salen)
{
	int rc = ::connect(sk, sa, salen);
	if (rc == -1 && errno != EINPROGRESS)
		return -1;
	return 0;
}

ssize_t Client :: os_write(int sk, const unsigned char *buf, size_t len)
{
	ssize_t rc = ::write(sk, buf, len);

	if (rc == -1 && errno == EAGAIN)
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	return rc;
}

ssize_t Client :: os_read(int sk, unsigned char *buf, size_t len)
{
	ssize_t rc = ::read(sk, buf, len);

	if (rc == -1 && errno == EAGAIN)
		return MBEDTLS_ERR_SSL_WANT_READ;
	return rc;
}

void Client :: os_close(int sk)
{
	close(sk);
}
