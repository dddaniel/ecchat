#include "contactwidget.hpp"
#include "client.hpp"
#include "mainwindow.hpp"

#include <QIcon>
#include <QDebug>

static QIcon *icon_offline;
static QIcon *icon_online;

extern Client *client;
extern MainWindow *m;

static void load_icons()
{
	icon_offline = new QIcon(":/offline.ico");
	icon_online = new QIcon(":/online.ico");
}

ContactWidget :: ContactWidget(struct contact *c)
	: contact(c)
{
	char idstr[ECCHAT_ID_MAXLEN + 2];
	QSize min;
	int min_x;
	int min_y;

	lbl = new QPushButton(this);
	icon_lbl = new QLabel(this);

	lbl->setFlat(true);

	if (icon_offline == NULL)
		load_icons();

	connect(lbl, SIGNAL(clicked()), this, SLOT(on_lbl_clicked()));

	ecchat_id2str(idstr, &c->id);
	lbl->setText(idstr);
	set_status(c->online);

	min = lbl->minimumSizeHint();
	min_x = min.width();
	min_y = min.height();
	setMinimumWidth(min_x + (min_x / 2));
	setMinimumHeight(min_y + (min_y / 2));
}

ContactWidget :: ~ContactWidget()
{
	delete lbl;
	delete icon_lbl;
}

bool ContactWidget :: event(QEvent *e)
{
	switch (e->type()) {
	case QEvent::Resize:
		resize_event();
		break;
	case QEvent::Enter:
		break;
	case QEvent::Leave:
		break;
	default:
		return QWidget::event(e);
	}
	return true;
}

void ContactWidget :: resize_event()
{
	const int w = width();
	const int h = height();
	const int w_icon = w / 10;
	const int h_icon = h;

	icon_lbl->setGeometry(0, 0, w_icon, h);
	lbl->setGeometry(w_icon, 0, w - w_icon, h);
	icon_lbl->setPixmap(ico->pixmap(w_icon, h_icon));
}

void ContactWidget :: on_lbl_clicked()
{
	m->open_chat(contact);
	if (contact->online)
		client->send_cmsg_request(contact);
}

void ContactWidget :: set_status(u16 status)
{
	if (status) {
		ico = icon_online;
	} else {
		ico = icon_offline;
	}

	resize_event();
}
