#ifndef CHATWIDGET_HPP
#define CHATWIDGET_HPP

#include <QTextEdit>
#include <QResizeEvent>
#include <QKeyEvent>
#include <QWidget>
#include <QVBoxLayout>
#include <QSpacerItem>
#include <QScrollArea>

#include "../ecchat.h"
#include "contact.h"

class ChatWidget;
class InputWidget;
class MsgWidget;

class ChatWidget : public QWidget
{
	Q_OBJECT
public:
	ChatWidget(struct contact *c);
	~ChatWidget();

	void add_msg_widget(MsgWidget *msg);
	void add_msg(const char *msg, bool local, bool err = false);
	void set_active();

	struct contact *contact;

protected:
	void resizeEvent(QResizeEvent *);

signals:
	void msg_added_signal();

private slots:
	void msg_added_slot();

private:
	QScrollArea *display;
	QVBoxLayout *msgs_layout;
	InputWidget *input;
};

class InputWidget : public QTextEdit
{
public:
	InputWidget(QWidget *parent, ChatWidget *);

protected:
	void keyPressEvent(QKeyEvent *e);
private:
	ChatWidget *chat_widget;
};
#endif
