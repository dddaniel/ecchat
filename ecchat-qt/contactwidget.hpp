#ifndef CONTACT_WIDGET_HPP
#define CONTACT_WIDGET_HPP

#include <QWidget>
#include <QEvent>
#include <QLabel>
#include <QPushButton>
#include <QIcon>

#include "../ecchat.h"
#include "contact.h"

struct contact;
class ContactWidget;

class ContactWidget : public QWidget
{
	Q_OBJECT
public:
	ContactWidget(struct contact *c);
	~ContactWidget();

	void set_status(u16 stauts);

protected:
	bool event(QEvent *);

private:
	void resize_event();

	QPushButton *lbl;
	QLabel *icon_lbl;
	QIcon *ico;
	struct contact *contact;

private slots:
	void on_lbl_clicked();
};


#endif
