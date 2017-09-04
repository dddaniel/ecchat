#include "chatwidget.hpp"

#include <QScrollBar>
#include <QCoreApplication>

InputWidget :: InputWidget(QWidget *parent, ChatWidget *cw)
	: QTextEdit(parent), chat_widget(cw)
{
}

ChatWidget :: ChatWidget(struct contact *c)
	: contact(c)
{
	QVBoxLayout *display_layout = new QVBoxLayout;

	msgs_layout = new QVBoxLayout;
	msgs_layout->setSpacing(0);
	display_layout->addLayout(msgs_layout);
        display_layout->addItem(new QSpacerItem(20, 40,
					QSizePolicy::Minimum,
					QSizePolicy::Expanding));

	QWidget *w = new QWidget;
	w->setLayout(display_layout);

	display = new QScrollArea(this);
	display->setWidgetResizable(true);
	display->setWidget(w);

	input = new InputWidget(this, this);

	connect(this, SIGNAL(msg_added_signal()),
		this, SLOT(msg_added_slot()),
		Qt::QueuedConnection);
}

ChatWidget :: ~ChatWidget()
{
	/* ~QWidget() cleans up child widgets */
}

void ChatWidget :: resizeEvent(QResizeEvent *)
{
	const int h = height();
	const int w = width();
	const int h_input = h / 8;
	const int h_display = h - h_input;

	display->setGeometry(0, 0, w, h_display);
	input->setGeometry(0, h_display, w, h_input);
}

void ChatWidget :: msg_added_slot()
{
	QScrollBar *b = display->verticalScrollBar();

	b->setValue(b->maximum());
}

void ChatWidget :: add_msg_widget(MsgWidget *msg)
{
	QWidget *w = display->widget();

	msgs_layout->addWidget(msg);
	w->resize(w->sizeHint());
	emit msg_added_signal();
}

void ChatWidget :: set_active()
{
	QWidget *w = display->widget();

	input->setFocus(Qt::ActiveWindowFocusReason);
	w->resize(w->sizeHint());
	emit msg_added_signal();
}

void InputWidget :: keyPressEvent(QKeyEvent *key)
{
	if (key->key() != Qt::Key_Return) {
		QTextEdit::keyPressEvent(key);
	} else {
		QByteArray b = toPlainText().toLatin1();
		const char *msg = b.data();

		clear();
		if (msg[0] == '\n' || msg[0] == '\r' || msg[0] == 0)
			return;
		contact_add_message(chat_widget->contact, msg, 1, 0);
	}
}
