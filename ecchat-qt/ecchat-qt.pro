QT += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
QMAKE_CXXFLAGS += -Wextra -g3 -O2
TARGET = ecchat-qt
RESOURCES = ecchat-qt.qrc

win32:{
	LIBS += -lws2_32
	LIBS += -L . -lmbedtls -lmbedcrypto -lmbedx509
	INCLUDEPATH += ../../mbedtls/include/
 	SOURCES += client_win.cpp
	RC_FILE = ecchat-qt.rc
}

linux:{
	LIBS += -lmbedtls -lmbedcrypto -lmbedx509
 	SOURCES += client_posix.cpp
	ICON = icon.ico
}

macx:{
	LIBS += -lmbedtls -lmbedcrypto -lmbedx509
 	SOURCES += client_posix.cpp
	ICON = icon.ico

	# plugin necessary because otherwise compatibility
	# version parameters are added, which are not
	# supported with bundles
	CONFIG += plugin
	QMAKE_LFLAGS_PLUGIN += -bundle

	INCLUDEPATH += /usr/local/include
	DEPENDPATH += /usr/locale/lib

	QMAKE_POST_LINK = install_name_tool -add_rpath @loader_path/.. ecchat-qt.app/Contents/MacOS/ecchat-qt
}

equals(STICK_WATCHDOG, 1) {
	message(build with stick watchdog)
	DEFINES += STICK_WATCHDOG=1
}

!isEmpty(DEF_SERVER) {
	message(build with default server $${DEF_SERVER})
	DEFINES += ECCHAT_SERVER_DEF=\"\\"\"$${DEF_SERVER}\"\\"\"
}

HEADERS += mainwindow.hpp \
		client.hpp \
		contactwidget.hpp \ 
		msgwidget.hpp \ 
		identitywidget.hpp \ 
		stick_wtd.hpp \
		chatwidget.hpp

SOURCES += main.cpp \
		mainwindow.cpp \
		client.cpp \
		contactwidget.cpp \
		chatwidget.cpp \
		msgwidget.cpp \
		identitywidget.cpp \ 
		stick_wtd.cpp \
		../txqueue.c \
		../crypto.c \
		../identity.c \
		contact.cpp

FORMS += mainwindow.ui \
	identitywidget.ui
