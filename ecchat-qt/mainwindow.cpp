#include "mainwindow.hpp"
#include "ui_mainwindow.h"
#include "contact.h"
#include "version.h"

#define QSTRING_CHAR(qstr) ((qstr).toLatin1().data())

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent),
	ui(new Ui::MainWindow)
{
	char title[32];

        ui->setupUi(this);
	sprintf(title, "ECchat Version %hu", ECCHAT_CLIENT_VERSION);
	setWindowTitle(title);
}

MainWindow :: ~MainWindow()
{
	delete ui;
}

void MainWindow :: add_contact(ContactWidget *w)
{
	ui->clist_layout->addWidget(w);
}

void MainWindow :: status_update(const char *msg)
{
	ui->statusBar->showMessage(msg);
}

void MainWindow :: contact_status_update(ecchat_id_t *id, u16 status)
{
	struct contact *c = contact_get(id);

	if (c == NULL) {
		char idstr[ECCHAT_ID_MAXLEN + 2];

		ecchat_id2str(idstr, id);
		err("unknown contact '%s' status received\n", idstr);
	}
	c->widget->set_status(status);
}

void MainWindow :: add_message_widget(struct contact *c, MsgWidget *msgw)
{
	create_chatwidget(c);
	c->chat_widget->add_msg_widget(msgw);
}

void MainWindow :: create_chatwidget(struct contact *uic)
{
	if (uic->chat_widget == NULL) {
		char idstr[ECCHAT_ID_MAXLEN + 2];

		ecchat_id2str(idstr, &uic->id);
		uic->chat_widget = new ChatWidget(uic);
		if (uic->chat_widget == NULL)
			return;

		ui->chats->addTab(uic->chat_widget, idstr);
	}
}

void MainWindow :: open_chat(struct contact *c)
{
	char idstr[ECCHAT_ID_MAXLEN + 2];
	int nchats, i;

	create_chatwidget(c);
	nchats = ui->chats->count();
	ecchat_id2str(idstr, &c->id);

	for (i = 0; i < nchats; i++) {
		QString tabname = ui->chats->tabText(i);

		if (!strcmp(QSTRING_CHAR(tabname), idstr)) {
			ui->chats->setCurrentIndex(i);
			on_chats_currentChanged(i);
		}
	}
}

void MainWindow :: on_chats_currentChanged(int idx)
{
	ChatWidget *w;

	if (idx == -1)
		return;

	w = (ChatWidget *)ui->chats->currentWidget();
	if (w)
		w->set_active();
}

void MainWindow :: on_chats_tabCloseRequested(int idx)
{
	ChatWidget *w = (ChatWidget *)ui->chats->widget(idx);

	ui->chats->removeTab(idx);
	contact_close_chat(w->contact);
}
