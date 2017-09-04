#include <QApplication>

#include <getopt.h>

#include "../ecchat.h"
#include "../crypto.h"
#include "../identity.h"
#include "mainwindow.hpp"
#include "client.hpp"
#include "contact.h"
#include "ecchat-qt.h"
#include "identitywidget.hpp"
#include "stick_wtd.hpp"

MainWindow *m;
Client *client;
struct identity identity;

#ifndef ECCHAT_SERVER_DEF
#define ECCHAT_SERVER_DEF "127.0.0.1"
#endif

struct options opts = {
	.wdir = ".",
	.server = ECCHAT_SERVER_DEF,
	.port = ECCHAT_TCP_PORT_DEF
};

static int parse_args(int argc, char **argv)
{
	static struct option long_options[] = {
		{ "server", required_argument, 0, 's' },
		{ "port", required_argument, 0, 'p' },
		{ "id", required_argument, 0, 'i' },
		{ 0, 0, 0, 0 }
	};
	int option_index = 0;
	int c;

	while ((c = getopt_long(argc, argv, "p:i:s:",
				long_options, &option_index)) != -1) {
		switch (c) {
		case 'p':
			opts.port = atoi(optarg);
			break;
		case 'i':
			opts.wdir = optarg;
			break;
		case 's':
			opts.server = optarg;
			break;
		default:
			return -1;
		}
	}
	return 0;
}

static int load_identity(QApplication *a)
{
	enum identity_rc load_rc = identity_load(&identity, opts.wdir);
	IdentityWidget *w;
	int rc;

	switch (load_rc) {
	case IDENTITY_LOAD_OK:
		rc = 0;
		break;
	case IDENTITY_LOAD_REQ_PWD:
		w = new IdentityWidget(&identity, opts.wdir);
		if (w == NULL) {
			rc = -1;
			break;
		}
		w->show();
		a->exec();
		rc = w->rc;
		delete w;
		break;
	default:
		rc = -1;
		break;
	}
	return rc;
}

int main(int argc, char *argv[])
{
        QApplication a(argc, argv);
	StickWtd stick_wtd;
	int rc = -1;

	if (parse_args(argc, argv) == -1)
		return -1;

	crypto_init();
	contacts_init();

	if (load_identity(&a) == -1) {
		identity_unload(&identity);
		return -1;
	}

	m = new MainWindow;
	client = new Client;
	if (client->init() == -1)
		goto out;

	stick_wtd.start();
	client->start();
        m->show();
        rc = a.exec();

out:
	identity_unload(&identity);
	crypto_deinit();
	contacts_free();
	delete client;
	delete m;
	return rc;
}
