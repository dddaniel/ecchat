#include "identitywidget.hpp"
#include "ui_identitywidget.h"

IdentityWidget :: IdentityWidget(struct identity *_id, const char *_dir)
	: id(_id), dir(_dir), ui(new Ui::IdentityWidget)
{
	ui->setupUi(this);
	rc = -1;
}

IdentityWidget :: ~IdentityWidget()
{
	delete ui;
}

void IdentityWidget :: on_ok_btn_clicked()
{
	QByteArray b = ui->pwd->text().toLatin1();
	const char *pwd = b.data();

	if (pwd[0] == 0)
		return;

	if (!identity_decrypt_private_key(id, dir, pwd, strlen(pwd))) {
		rc = 0;
		close();
	} else {
		rc = -1;
		QPalette p(ui->pwd->palette());
		p.setColor(QPalette::Background, Qt::red);
		ui->pwd->setPalette(p);
		ui->pwd->setAutoFillBackground(true);
	}
}
