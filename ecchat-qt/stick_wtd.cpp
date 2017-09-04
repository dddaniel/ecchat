#include "stick_wtd.hpp"

#ifdef STICK_WATCHDOG

#include "ecchat-qt.h"
#include "../ecchat.h"

#include <unistd.h>
#include <QCoreApplication>

extern struct options opts;

StickWtd :: StickWtd()
{
	connect(&timer, &QTimer::timeout, this, &StickWtd::timer_cb);
}

void StickWtd :: start()
{
	timer.start(INTERVAL_MSEC);
}

void StickWtd :: timer_cb()
{
	char ca_file[PATH_MAX];

	sprintf(ca_file, "%s/%s", opts.wdir, "ca-cert.pem");
	if (access(ca_file, F_OK) != 0)
		QCoreApplication::quit();
}

#else

StickWtd :: StickWtd()
{
}

void StickWtd :: start()
{
}

void StickWtd :: timer_cb()
{
}

#endif
