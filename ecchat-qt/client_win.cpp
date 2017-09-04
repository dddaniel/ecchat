#include "client.hpp"
#include <windows.h>

static int wsa_last_err;

static const char *wsa_strerror(int err)
{
	switch (err) {
	case WSAEWOULDBLOCK:
		return "Operation in Progress";
	case WSAENOTCONN:
		return "Broken Pipe";
	default:
		return "unkown";
	}
}

static int wsa2ssl_err(int wsa_err, bool rd)
{
	switch (wsa_err) {
	case WSAEWOULDBLOCK:
		if (rd)
			return MBEDTLS_ERR_SSL_WANT_READ;
	       	else
			return MBEDTLS_ERR_SSL_WANT_WRITE;
	default:
		return MBEDTLS_ERR_SSL_CONN_EOF;
	}
}

int Client :: os_init()
{
        WSADATA wsaData;
	int rc;

        rc = WSAStartup(MAKEWORD(1, 1), &wsaData);
	if (rc)
		err("WSAStartup failed\n");
	return rc;
}

void Client :: set_nonblock()
{
	unsigned long mode = 1;
	ioctlsocket(sk, FIONBIO, &mode);
}

void Client :: sk_error(const char *msg)
{
	err("%s: %s (%u)\n", msg, wsa_strerror(wsa_last_err), wsa_last_err);
}

int Client :: os_connect(int sk, struct sockaddr *sa, unsigned long salen)
{
	int rc = ::connect(sk, sa, salen);
	if (rc == -1) {
		wsa_last_err = WSAGetLastError();
		if (wsa_last_err != WSAEWOULDBLOCK)
			return -1;
	}
	return 0;
}

ssize_t Client :: os_write(int sk, const unsigned char *buf, size_t len)
{
	ssize_t rc = ::send(sk, (const char *)buf, len, 0);

	if (rc == -1) {
		wsa_last_err = WSAGetLastError();
		rc = wsa2ssl_err(wsa_last_err, false);
	}
	return rc;
}

ssize_t Client :: os_read(int sk, unsigned char *buf, size_t len)
{
	ssize_t rc = ::recv(sk, (char *)buf, len, 0);

	if (rc == -1) {
		wsa_last_err = WSAGetLastError();
		rc = wsa2ssl_err(wsa_last_err, true);
	}
	return rc;
}

void Client :: os_close(int sk)
{
	closesocket(sk);
}
