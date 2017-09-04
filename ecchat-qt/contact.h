#ifndef CONTACT_H
#define CONTACT_H

#include <QWidget>
#include <mbedtls/ecp.h>

#include "contactwidget.hpp"
#include "chatwidget.hpp"
#include "msgwidget.hpp"

#include "../ecchat.h"
#include "../txqueue.h"
#include "../list.h"

class ChatWidget;
class ContactWidget;
class MsgWidget;

struct msg {
	struct list_head list;
	MsgWidget *widget;
	u16 id;
	u8 local:1; /* locally generated */
	u8 error:1; /* local error message */
	u8 sent:1;
	u8 acked:1;
};

struct contact {
	ChatWidget *chat_widget;
	ContactWidget *widget;
	ecchat_id_t id;
	u16 msgid_last;

	mbedtls_ecp_keypair key;
	mbedtls_ecp_keypair key_offline;
	unsigned char session_key[32];
	unsigned char offline_key[32];

	u8 session_estab:1;
	u8 session_init:1;
	u8 online:1;

	/* unsent messages */
	struct list_head msgs_nsent;
	/* unacked messages */
	struct list_head msgs_nack;
	/* acked/received messages */
	struct list_head msgs_completed;

	/* contact list entry */
	struct list_head list;
};

void contact_session_clear(struct contact *c);
void contact_add_message(struct contact *c, const char *msg, int local, int err);
void contact_del_message(struct msg *msg);
void contact_clear_messages(struct contact *c);
void contact_close_chat(struct contact *c);
void contact_session_established(struct contact *c);
void contact_ack_message(struct contact *c, u16 id);
void contact_set_status(struct contact *c, u16 status);
struct contact * contact_get(const ecchat_id_t *id);

void contacts_init();
void contacts_free();
void contacts_set_offline();
void contacts_update(const struct ecchat_msg_clist_entry *e,
			const unsigned n_entries);

#endif
