#ifndef TXQUEUE_H
#define TXQUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include "list.h"

typedef ssize_t (*txfn_t)(void *ctx, const void *msg, size_t len);

struct tx_queue_entry {
	struct list_head list;
	char *data;
	unsigned len;
};

struct tx_queue {
	struct list_head head;
	unsigned cnt;
	unsigned max;
};

static inline void tx_queue_init(struct tx_queue *q, const unsigned max)
{
	INIT_LIST_HEAD(&q->head);
	q->cnt = 0;
	q->max = max;
}

void tx_queue_add(struct tx_queue *q, const void *data, unsigned len);
void tx_queue_del(struct tx_queue *q, struct tx_queue_entry *e);
void tx_queue_deinit(struct tx_queue *q);
void tx_queue_move(struct tx_queue *dst, struct tx_queue *src);
unsigned tx_queue_flush(struct tx_queue *q, txfn_t txfn, void *tx_fn_ctx);

#ifdef __cplusplus
}
#endif

#endif
