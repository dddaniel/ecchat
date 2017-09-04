#include "msgwidget.hpp"

#include <QDateTime>

MsgWidget :: MsgWidget(const char *txt, bool local, bool err)
{
	QSize min;
	QFont font;
	int min_x;
	int min_y;

	lbl = new QLabel(this);
	lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);

	date_lbl = new QLabel(this);
	font = date_lbl->font();
	font.setItalic(true);
	date_lbl->setFont(font);

	set_txt(txt);

	if (err) {
		set_bg(255, 0, 0, 70);
	} else if (local) {
		set_bg(0, 0, 255, 30);
	} else {
		set_bg(0, 0, 0, 0);
		font = lbl->font();
		font.setBold(true);
		lbl->setFont(font);
	}

	min = lbl->minimumSizeHint();
	min_x = min.width();
	min_y = min.height();
	setMinimumWidth(min_x + (min_x / 2));
	setMinimumHeight(min_y + (min_y / 2));

	setAutoFillBackground(true);
}

MsgWidget :: ~MsgWidget()
{
}

void MsgWidget :: set_txt(const char *txt)
{
	QString date = QDateTime::currentDateTime().toString("dd.MM hh:mm");

	date_lbl->setText(date + ":  ");
	lbl->setText(QString::fromLatin1(txt));
}

void MsgWidget :: resizeEvent(QResizeEvent *)
{
	const int h = height();
	const int w = width();
	const int date_w = date_lbl->minimumSizeHint().width();
	const int msg_w = w - date_w;

	date_lbl->setGeometry(0, 0, date_w, h);
	lbl->setGeometry(date_w, 0, msg_w, h);
}

void MsgWidget :: set_bg(int r, int g, int b, int a)
{
	QColor col(r, g, b, a);
	QPalette p(palette());
	p.setColor(QPalette::Background, col);
	setPalette(p);
}

void MsgWidget :: set_acked()
{
	set_bg(0, 255, 0, 60);
}
