#ifndef IDENTITYWIDGET_HPP
#define IDENTITYWIDGET_HPP

#include "../identity.h"
#include <QWidget>

namespace Ui {
    class IdentityWidget;
}

class IdentityWidget : public QWidget
{
	Q_OBJECT
public:
	IdentityWidget(struct identity *id, const char *dir);
	~IdentityWidget();

	int rc;

private slots:
	void on_ok_btn_clicked();

private:
	struct identity *id;
	const char *dir;

        Ui::IdentityWidget *ui;
};

#endif
