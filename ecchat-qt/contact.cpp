#include "contact.h"
#include "mainwindow.hpp"
#include "client.hpp"
#include "ecchat-qt.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define CDATA_DIR_PERM	(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IROTH)
#define CDATA_FILE_PERM	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern MainWindow *m;
extern Client *client;
extern struct options opts;

static LIST_HEAD(contacts);

struct contact * contact_get(const ecchat_id_t *id)
{
	struct contact *c;
	struct contact *c_match = NULL;

	list_for_each_entry(c, &contacts, list) {
		if (!ecchat_id_cmp(&c->id, id)) {
			c_match = c;
			break;
		}
	}
	if (c_match == NULL)
		err("unkonwn contact: %s\n", ecchat_idstr(id));

	return c_match;
}

static void contact_offline_key(struct contact *c, bool wr)
{
	char path[PATH_MAX + 1];
	ssize_t rc;
	int fd;
	int flags;

	sprintf(path, "%s/cdata/%s", opts.wdir, ecchat_idstr(&c->id));

	if (wr)
		flags = O_WRONLY | O_CREAT | O_TRUNC;
	else
		flags = O_RDONLY;

	fd = open(path, flags, CDATA_FILE_PERM);
	if (fd == -1) {
		err_errno("%s", path);
		return;
	}

	if (wr)
		rc = write(fd, c->offline_key, sizeof(c->offline_key));
	else
		rc = read(fd, c->offline_key, sizeof(c->offline_key));

	if (rc != (ssize_t)sizeof(c->offline_key))
		err_errno("%s", path);

	close(fd);
}

static void mkdir_cdata()
{
	char path[PATH_MAX + 1];

	sprintf(path, "%s/cdata", opts.wdir);

#if defined(_WIN64) || defined(_WIN32)
	mkdir(path);
#else
	mkdir(path, CDATA_DIR_PERM);
#endif
}

void contacts_init()
{
	mkdir_cdata();
}

static void contact_load_offline_key(struct contact *c)
{
	contact_offline_key(c, false);
}

static void contact_store_offline_key(struct contact *c)
{
	contact_offline_key(c, true);
}

static void
contact_init(struct contact *u, const struct ecchat_msg_clist_entry *e)
{
	u->id = e->id;
	u->online = e->status;
	u->widget = new ContactWidget(u);
	u->chat_widget = NULL;
	u->msgid_last = 0;

	INIT_LIST_HEAD(&u->msgs_nsent);
	INIT_LIST_HEAD(&u->msgs_nack);
	INIT_LIST_HEAD(&u->msgs_completed);

	mbedtls_ecp_keypair_init(&u->key);
	mbedtls_ecp_keypair_init(&u->key_offline);

	memset(u->session_key, 0x00, sizeof(u->session_key));
	memset(u->offline_key, 0xdc, sizeof(u->offline_key));

	u->session_estab = false;
	u->session_init = false;

	contact_load_offline_key(u);
	list_add_tail(&u->list, &contacts);
}

static struct contact * contact_new(const struct ecchat_msg_clist_entry *e)
{
	struct contact *c = new struct contact;

	if (c)
		contact_init(c, e);
	return c;
}

static void contact_free(struct contact *u, bool del_widgets = false)
{
	mbedtls_ecp_keypair_free(&u->key);
	mbedtls_ecp_keypair_free(&u->key_offline);

	if (del_widgets) {
		contact_close_chat(u);
		delete u->widget;
	} else {
		/* widgets get destroyed by mainwindow */
	}
	list_del(&u->list);
}

static int id_is_on_clist(const ecchat_id_t *id,
			const struct ecchat_msg_clist_entry *e,
			const unsigned n_entries)
{
	unsigned i;

	for (i = 0; i < n_entries; i++) {
		const struct ecchat_msg_clist_entry *cle = &e[i];

		if (!ecchat_id_cmp(id, &cle->id))
			return 1;
	}
	return 0;
}

void contacts_update(const struct ecchat_msg_clist_entry *e,
			const unsigned n_entries)
{
	struct contact *c, *tmp;
	unsigned i;

	/* add new or update status
	 */
	for (i = 0; i < n_entries; i++) {
		const struct ecchat_msg_clist_entry *cle = &e[i];
		struct contact *c = contact_get(&cle->id);

		if (c) {
			contact_set_status(c, cle->status);
		} else {
			struct contact *c_new = contact_new(cle);

			err("add new: %s\n", ecchat_idstr(&c_new->id));
			m->add_contact(c_new->widget);
		}
	}

	/* delete contacts that are no longer on clist
	 */
	list_for_each_entry_safe(c, tmp, &contacts, list) {
		if (!id_is_on_clist(&c->id, e, n_entries))
			contact_free(c, true);
	}
}

void contact_session_clear(struct contact *c)
{
	mbedtls_ecp_keypair_free(&c->key);
	mbedtls_ecp_keypair_free(&c->key_offline);
	memset(c->session_key, 0, sizeof(c->session_key));
	/* keep c->offline_key */
	c->session_estab = false;
	c->session_init = false;
}

void contact_clear_messages(struct contact *c)
{
	struct msg *msg, *tmp;

	list_for_each_entry_safe(msg, tmp, &c->msgs_nsent, list)
		contact_del_message(msg);

	list_for_each_entry_safe(msg, tmp, &c->msgs_nack, list)
		contact_del_message(msg);

	list_for_each_entry_safe(msg, tmp, &c->msgs_completed, list)
		contact_del_message(msg);
}

void contact_del_message(struct msg *msg)
{
	if (msg->widget)
		delete msg->widget;

	if (msg->list.next)
		list_del(&msg->list);

	delete msg;
}

void contact_add_message(struct contact *c, const char *txt, int local, int err)
{
	struct msg *msg = new struct msg;

	if (msg == NULL)
		return;

	memset(msg, 0, sizeof(*msg));
	msg->id = c->msgid_last++;
	msg->local = local;
	msg->error = err;
	msg->widget = new MsgWidget(txt, local, err);

	m->add_message_widget(c, msg->widget);

	if (local && !err) {
		int rc = client->send_cmsg_msg(c, msg->id, txt, strlen(txt) + 1);

		if (rc > 0) {
			msg->sent = 1;
			list_add_tail(&msg->list, &c->msgs_nack);
		} else if (rc == -2) {
			contact_del_message(msg);
		} else {
			list_add_tail(&msg->list, &c->msgs_nsent);
		}
	} else {
		list_add_tail(&msg->list, &c->msgs_completed);
	}
}

void contact_ack_message(struct contact *c, u16 id)
{
	struct msg *m;
	struct msg *msg = NULL;

	err("%hu\n", id);
	list_for_each_entry(m, &c->msgs_nack, list) {
		if (m->id == id) {
			msg = m;
			break;
		}
	}
	if (msg == NULL) {
		err("ack for unkown message received\n");
		return;
	}

	list_move_tail(&msg->list, &c->msgs_completed);
	msg->acked = 1;
	msg->widget->set_acked();
}

void contact_close_chat(struct contact *c)
{
	contact_clear_messages(c);
	contact_session_clear(c);

	if (c->chat_widget) {
		delete c->chat_widget;
		c->chat_widget = NULL;
	}
}

void contact_flush_messages(struct contact *c,
			struct list_head *cur_list,
			struct list_head *target_list)
{
	struct msg *msg, *tmp;

	list_for_each_entry_safe(msg, tmp, cur_list, list) {
		QString txt_str = msg->widget->lbl->text();
		QByteArray b = txt_str.toLatin1();
		const char *txt = b.data();

		int rc = client->send_cmsg_msg(c, msg->id, txt, strlen(txt) + 1);
		if (rc > 0) {
			msg->sent = 1;
			if (target_list)
				list_move_tail(&msg->list, target_list);
		}
	}
}

void contact_session_established(struct contact *c)
{
	/* free keypairs, keep secrect session and offline key */
	mbedtls_ecp_keypair_free(&c->key);
	mbedtls_ecp_keypair_free(&c->key_offline);

	c->session_init = false;
	c->session_estab = true;
	contact_flush_messages(c, &c->msgs_nack, NULL);
	contact_flush_messages(c, &c->msgs_nsent, &c->msgs_nack);

	contact_store_offline_key(c);
}

void contact_set_status(struct contact *c, u16 status)
{
	if (c->online == status)
		return;

	c->online = status;
	if (c->online == false)
		contact_session_clear(c);

	m->contact_status_update(&c->id, status);
}

void contacts_set_offline()
{
	struct contact *c;

	list_for_each_entry(c, &contacts, list)
		contact_set_status(c, 0);
}

void contacts_free()
{
	struct contact *c, *tmp;

	list_for_each_entry_safe(c, tmp, &contacts, list)
		contact_free(c);
}

