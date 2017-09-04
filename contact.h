#ifndef CONTACT_H
#define CONTACT_H

#include "ecchat.h"
#include "avl.h"
#include "txqueue.h"

struct contact {
	ecchat_id_t id;
	struct ecchat_clist clist;
	struct tx_queue mbox;
	void *priv;
	u8 online;
	u8 latest_client_version;

	struct avl_node node;
};

typedef void (*contact_moved_cb)(struct contact *contact);
typedef void (*contact_deleted_cb)(struct contact *contact);

struct contacts {
	struct avl_tree tree;
	contact_moved_cb contact_moved;
	contact_deleted_cb contact_deleted;
};

void contacts_init();
struct contacts * contacts_new(contact_moved_cb mov_cb,
				contact_deleted_cb del_cb);
void contacts_free(struct contacts *contacts);
int contacts_load(struct contacts *contacts);
struct contact * contact_get(struct contacts *contacts, const ecchat_id_t *id);
void contacts_move_state(struct contacts *contacts_new,
			struct contacts *contacts_old);

void contact_mbox_add(struct contact *c, const char *msg, const unsigned len);
void contact_mbox_del(struct contact *c);
void contact_mbox_truncate(struct contact *c);

static inline void contact_print(struct contact *c)
{
	char idstr[ECCHAT_ID_MAXLEN + 2];

	ecchat_id2str(idstr, &c->id);
	printf("contact: %s online %hu\n", idstr, c->online);
	ecchat_clist_print(&c->clist);
}

#endif
