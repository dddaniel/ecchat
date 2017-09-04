#include "contact.h"
#include "ecchat.h"
#include "txqueue.h"

#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define EOF_PTR (char *)EOF
#define MBOX_DIR_PERM	(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IROTH)
#define MBOX_FILE_PERM	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)


static struct contact *
contact_new(struct contacts *contacts, const char *name)
{
	struct contact *c;

	if (strlen(name) > ECCHAT_ID_MAXLEN) {
		err("contact name to long: %s\n", name);
		return NULL;
	}

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		err("%s: out of memory\n", name);
		return NULL;
	}
	ecchat_str2id(&c->id, name);
	tx_queue_init(&c->mbox, 128);
	c->node.key = &c->id;
	avl_insert(&contacts->tree, &c->node);
	return c;
}

static void contact_free(struct contacts *contacts, struct contact *c)
{
	avl_delete(&contacts->tree, &c->node);
	free(c->clist.entries);
	tx_queue_deinit(&c->mbox);
	free(c);
}

static char * contact_parse_id_line(char *buf, unsigned buflen, FILE *f)
{
	char *id = fgets(buf, buflen - 1, f);
	unsigned idlen;

	if (id == NULL)
		return EOF_PTR;

	idlen = strlen(id) - 1;
	id[idlen--] = 0;

	if (idlen == 0)
		return NULL;

	if (idlen > ECCHAT_ID_MAXLEN) {
		err("id exceeds maxlen: %s\n", id);
		return NULL;
	}
	return id;
}

static void contact_store_mbox(struct contact *c,
				const char *msg, const unsigned len,
				const int append)
{
	char path[PATH_MAX + 1];
	int flags = O_WRONLY | O_CREAT;
	int fd;

	if (append)
		flags |= O_APPEND;
	else
		flags |= O_TRUNC;

	sprintf(path, "./contacts/mbox/%s", ecchat_idstr(&c->id));
	fd = open(path, flags, MBOX_FILE_PERM);
	if (fd == -1) {
		err_errno("open %s", path);
		return;
	}
	if (write(fd, msg, len) == -1)
		err_errno("write %s", path);

	close(fd);
}

static void contact_load_mbox(struct contact *c, const char *name)
{
	char path[PATH_MAX + 1];
	int fd;

	sprintf(path, "./contacts/mbox/%s", name);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			err_errno("open %s", path);
		return;
	}

	for (;;) {
		char buf[2048];
		ssize_t len;

		len = read(fd, buf, sizeof(buf));
		if (len <= 0) {
			if (len == -1)
				err_errno("read %s", path);
			break;
		}
		tx_queue_add(&c->mbox, buf, len);
	}
	close(fd);
}

static int contact_load_clist(struct ecchat_clist *cl, const char *name)
{
	char path[PATH_MAX + 1];
	char line[128];
	FILE *f;
	char *id = NULL;
	unsigned ids = 0;
	unsigned i = 0;
	int rc = 0;

	sprintf(path, "./contacts/%s", name);
	f = fopen(path, "r");
	if (f == NULL) {
		err_errno("open %s", path);
		return -1;
	}

	/* parse contact list
	 */
	do {
		id = contact_parse_id_line(line, sizeof(line), f);
		if (id && id != EOF_PTR)
			ids++;
	} while (id != EOF_PTR);

	if (ids == 0) {
		err("contact '%s' has empty contact list\n", name);
		rc = -1;
		goto out;
	}

	cl->n_entries = ids;
	cl->entries = calloc(sizeof(struct ecchat_clist_entry), ids);
	if (cl->entries == NULL) {
		rc = -1;
		goto out;
	}

	rewind(f);

	do {
		id = contact_parse_id_line(line, sizeof(line), f);
		if (id && id != EOF_PTR)
			ecchat_str2id(&cl->entries[i++].id, id);
	} while (id != EOF_PTR);

out:
	fclose(f);
	return rc;
}

struct contact * contact_get(struct contacts *contacts, const ecchat_id_t *id)
{
	struct avl_node *n = avl_find(&contacts->tree, id);

	if (n == NULL)
		return NULL;

	return container_of(n, struct contact, node);
}

static int contact_id_is_on_clist(const ecchat_id_t *id,
				const struct ecchat_clist *cl)
{
	unsigned i;

	for (i = 0; i < cl->n_entries; i++) {
		const struct ecchat_clist_entry *e = &cl->entries[i];

		if (!ecchat_id_cmp(id, &e->id))
			return 1;
	}
	return 0;
}

static int contacts_check_clists(struct contacts *contacts)
{
	char idstr[ECCHAT_ID_MAXLEN + 2];
	char idstr_ref[ECCHAT_ID_MAXLEN + 2];
	struct contact *c;

	avl_for_each_element(&contacts->tree, c, node) {
		const struct ecchat_clist *cl = &c->clist;
		unsigned i;

		for (i = 0; i < cl->n_entries; i++) {
			const struct ecchat_clist_entry *e = &cl->entries[i];
			const struct contact *cl_c = e->ref;

			if (!contact_id_is_on_clist(&c->id, &cl_c->clist)) {
				ecchat_id2str(idstr, &c->id);
				ecchat_id2str(idstr_ref, &e->id);
				err("'%s' knows '%s', but not the other way\n",
					idstr, idstr_ref);
				return -1;
			}
		}
	}
	return 0;
}

static int contacts_build_xref(struct contacts *contacts)
{
	char idstr[ECCHAT_ID_MAXLEN + 2];
	char idstr_cur[ECCHAT_ID_MAXLEN + 2];
	struct contact *c;
	unsigned n;

	avl_for_each_element(&contacts->tree, c, node) {
		struct ecchat_clist *cl = &c->clist;

		for (n = 0; n < cl->n_entries; n++) {
			struct ecchat_clist_entry *e = &cl->entries[n];
			struct contact *c_ref = contact_get(contacts, &e->id);

			if (c_ref == NULL) {
				ecchat_id2str(idstr, &e->id);
				ecchat_id2str(idstr_cur, &c->id);
				err("contact '%s' clist[%02u]='%s' not found\n",
					idstr_cur, n, idstr);
				return -1;
			}
			if (c_ref == c) {
				ecchat_id2str(idstr, &e->id);
				ecchat_id2str(idstr_cur, &c->id);
				err("contact '%s' clist[%02u]='%s' contacts himself\n",
					idstr_cur, n, idstr);
				return -1;
			}
			e->ref = c_ref;
		}
	}
	return 0;
}

static void contact_move_state(struct contact *dst, struct contact *src)
{
	dst->online = src->online;
	src->online = 0;
	dst->priv = src->priv;
	src->priv = NULL;
	tx_queue_move(&dst->mbox, &src->mbox);
}

void contacts_move_state(struct contacts *contacts_new,
			struct contacts *contacts_old)
{
	struct contact *c_new;

	avl_for_each_element(&contacts_new->tree, c_new, node) {
		struct contact *c_old = contact_get(contacts_old, &c_new->id);

		if (c_old) {
			contact_move_state(c_new, c_old);
			contacts_new->contact_moved(c_new);
		}
	}
}

int contacts_load(struct contacts *contacts)
{
	DIR *d = opendir("./contacts");
	struct dirent *de;
	unsigned cnt = 0;
	int rc = 0;

	if (d == NULL) {
		err_errno("open dir");
		return -1;
	}

	while ((de = readdir(d))) {
		const char *name = de->d_name;
		struct contact *c;

		if (name[0] == '.' || de->d_type != DT_REG)
			continue;

		c = contact_new(contacts, name);
		if (c == NULL) {
			rc = -1;
			break;
		}
		rc = contact_load_clist(&c->clist, name);
		if (rc == -1)
			break;

		contact_load_mbox(c, name);
		contact_print(c);
		cnt++;
	}
	closedir(d);

	if (cnt == 0) {
		err("no contacts\n");
		rc = -1;
	} else {
		rc = contacts_build_xref(contacts);
		if (!rc)
			rc = contacts_check_clists(contacts);
	}
	return rc;
}

static int contact_cmp(const void *k1, const void *k2, __unused void *priv)
{
	const struct contact *c1 = k1;
	const struct contact *c2 = k2;

	return ecchat_id_cmp(&c1->id, &c2->id);
}

void contacts_init()
{
	int rc = mkdir("./contacts/mbox", MBOX_DIR_PERM);

	if (rc == -1 && errno != EEXIST)
		err_errno("mkdir ./contacts/mbox");
}

struct contacts * contacts_new(contact_moved_cb mov_cb,
				contact_deleted_cb del_cb)
{
	struct contacts *contacts = malloc(sizeof(*contacts));

	if (contacts) {
		avl_init(&contacts->tree, contact_cmp, false, NULL);
		contacts->contact_moved = mov_cb;
		contacts->contact_deleted = del_cb;
	}
	return contacts;
}

void contacts_free(struct contacts *contacts)
{
	struct contact *c, *tmp;

	avl_for_each_element_safe(&contacts->tree, c, node, tmp) {
		contacts->contact_deleted(c);
		contact_free(contacts, c);
	}
	free(contacts);
}

void contact_mbox_add(struct contact *c, const char *msg, const unsigned len)
{
	tx_queue_add(&c->mbox, msg, len);
	contact_store_mbox(c, msg, len, 1);
}

void contact_mbox_del(struct contact *c)
{
	char path[PATH_MAX + 1];
	int rc;

	sprintf(path, "./contacts/mbox/%s", ecchat_idstr(&c->id));
	rc = unlink(path);
	if (rc == -1 && errno != ENOENT)
		err_errno("unlink %s", path);
}

void contact_mbox_truncate(struct contact *c)
{
	struct tx_queue_entry *e;
	int first = 1;

	list_for_each_entry(e, &c->mbox.head, list) {
		if (first) {
			contact_store_mbox(c, e->data, e->len, 0);
			first = 0;
		}
		contact_store_mbox(c, e->data, e->len, 1);
	}
}
