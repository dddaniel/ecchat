#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <QSocketNotifier>
#include <QEvent>
#include <QTimer>

#include "../buffer.h"
#include "../ecchat.h"
#include "../crypto.h"

class Client;

class Client_notifier : public QSocketNotifier
{
	Q_OBJECT
public:
	Client_notifier(qintptr sk, QSocketNotifier::Type t, Client *p);
	~Client_notifier();

private slots:
	void on_activated(int sk);

private:
	Client *parent;
};

class Client : public QObject
{
	Q_OBJECT
public:
	Client();
	~Client();

	enum state {
		STATE_DISCONNECTED,
		STATE_CONNECTING,
		STATE_SSL_INIT,
		STATE_SSL_CONNECTED
	};

	int init();
	void start();
	void stop();
	void reconnect(bool delayed = true);
	int input(char *msg, unsigned len);
	void connected();
	void connection_ready();

	int send_cmsg_msg(struct contact *c,
			const u16 id,
			const char *msg,
			const unsigned len);
	void send_cmsg_request(struct contact *c);
	void send_cmsg_response(struct contact *c);
	void send_server_msg(enum ecchat_hdr_type t);
	void send_get_clist();
	void send_cmsg_ack(struct contact *c, u16 id);

	void do_read();
	void do_write();

	/* os specific */
	void set_nonblock();
	int os_init();
	void sk_error(const char *msg);
	int os_connect(int sk, struct sockaddr *sa, unsigned long salen);
	ssize_t os_write(int sk, const unsigned char *buf, size_t len);
	ssize_t os_read(int sk, unsigned char *buf, size_t len);
	void os_close(int sk);

	int sk;
	struct tls_ctx tls;

private slots:
	void connect_timer_cb();
	void reconnect_timer_cb();
	void keepalive_timer_cb();
	void msg_timeout_timer_cb();

private:
	int _start();
	void check_ssl_state();
	void set_state(enum state s);
	int send(const char *msg, size_t len);
	int send_cmsg_req_res(struct contact *c, bool is_req);

	void msg_received();

	void rcv_cmsg_req_res(char *buf, bool key_regen);
	void rcv_cmsg_request(char *buf);
	void rcv_cmsg_response(char *buf);
	void rcv_clist(char *buf);
	void rcv_mbox(char *buf);
	void rcv_cmsg_msg(char *buf, bool offline_msg = false);
	void rcv_cmsg_ack(char *buf);

	Client_notifier *notif_rd;
	Client_notifier *notif_wr;
	QTimer connect_timer;
	QTimer reconnect_timer;
	QTimer keepalive_timer;
	QTimer msg_timeout_timer;
	enum state state;

	struct buffer buf;

	static const int RECONNECT_INT_MSEC = 4 * 1000;
	static const int CONNECT_TIMO_MSEC = 8 * 1000;
};

#endif
