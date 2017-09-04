#ifndef MSGWIDGET_HPP
#define MSGWIDGET_HPP

#include <QWidget>
#include <QFrame>
#include <QLabel>
#include <QResizeEvent>

#include "contact.h"

class MsgWidget : public QFrame
{
	Q_OBJECT
public:
	MsgWidget(const char *txt, bool local, bool err);
	~MsgWidget();

	void set_txt(const char *txt);
	void set_acked();
	QLabel *lbl;

protected:
	void resizeEvent(QResizeEvent *);

private:
	QLabel *date_lbl;
	void set_bg(int r, int g, int b, int a);
};

#endif
