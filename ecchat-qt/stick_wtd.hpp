#ifndef STICKWDT_HPP
#define STICKWDT_HPP

#include <QTimer>

class StickWtd : public QObject
{
	Q_OBJECT
public:
	StickWtd();
	void start();

private slots:
	void timer_cb();

private:
	QTimer timer;
	static const unsigned INTERVAL_MSEC = 1000;
};

#endif
