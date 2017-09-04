#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include <QResizeEvent>
#include <QWidget>

#include "../ecchat.h"
#include "msgwidget.hpp"
#include "contactwidget.hpp"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
        Q_OBJECT

public:
	explicit MainWindow(QWidget *parent = NULL);
	~MainWindow();

	void contact_status_update(ecchat_id_t *id, u16 status);
	void status_update(const char *msg);
	void add_contact(ContactWidget *w);
	void add_message(struct contact *c, const char *msg, bool err = false);
	void add_message_widget(struct contact *c, MsgWidget *msgw);
	void open_chat(struct contact *c);

private slots:
	void on_chats_currentChanged(int);
	void on_chats_tabCloseRequested(int);

private:
	void create_chatwidget(struct contact *uic);

        Ui::MainWindow *ui;
};

#endif
