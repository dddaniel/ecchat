#include "txqueue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tx_queue_add(struct tx_queue *q, const void *data, unsigned len)
{
	struct tx_queue_entry *e;
	char *d;

	if (q->cnt >= q->max) {
		fprintf(stderr, "tx queue overrun, dropping\n");
		return;
	}

	d = malloc(len);
	e= malloc(sizeof(*e));
	if (e == NULL || d == NULL) {
		fprintf(stderr, "out of memory\n");
		free(e);
		free(d);
		return;
	}

	memcpy(d, data, len);
	e->data = d;
	e->len = len;
	list_add_tail(&e->list, &q->head);
	q->cnt += 1;
}

void tx_queue_del(struct tx_queue *q, struct tx_queue_entry *e)
{
	list_del(&e->list);
	free(e->data);
	free(e);
	q->cnt -= 1;
}

void tx_queue_deinit(struct tx_queue *q)
{
	struct tx_queue_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, &q->head, list)
		tx_queue_del(q, e);
}

static void tx_queue_entry_consume(struct tx_queue_entry *e, unsigned bytes)
{
	const unsigned newlen = e->len - bytes;
	char *new_data = malloc(newlen);

	if (new_data == NULL) {
		fprintf(stderr, "out of memory\n");
		return;
	}

	memcpy(new_data, &e->data[bytes], newlen);
	free(e->data);
	e->len = newlen;
	e->data = new_data;
	return;
}

unsigned tx_queue_flush(struct tx_queue *q, txfn_t txfn, void *txfn_ctx)
{
	struct tx_queue_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, &q->head, list) {
		ssize_t rc = txfn(txfn_ctx, e->data, e->len);
		if (rc == (ssize_t)e->len) {
			tx_queue_del(q, e);
		} else if (rc <= 0) {
			break;
		} else {
			tx_queue_entry_consume(e, rc);
			break;
		}
	}
	return q->cnt;
}

void tx_queue_move(struct tx_queue *dst, struct tx_queue *src)
{
	struct tx_queue_entry *e, *tmp;

	tx_queue_init(dst, src->max);
	dst->cnt = src->cnt;

	list_for_each_entry_safe(e, tmp, &src->head, list)
		list_move_tail(&e->list, &dst->head);
	src->cnt = 0;
}
