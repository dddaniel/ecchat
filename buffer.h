#ifndef BUFFER_H
#define BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_BS	1024

struct buffer {
	char *data;
	size_t len;
	size_t wr_pos;
	size_t rd_pos;
};

static inline char * buffer_data(struct buffer *b)
{
	return &b->data[b->rd_pos];
}

static inline size_t buffer_len(struct buffer *b)
{
	return b->wr_pos - b->rd_pos;
}

static inline int buffer_resize(struct buffer *b, size_t newlen)
{
	char *d = (char *)realloc(b->data, newlen);

	if (d == NULL)
		return -1;

	b->data = d;
	b->len = newlen;
	return 0;
}

static inline int buffer_alloc(struct buffer *b, size_t reqlen)
{
	int rc = 0;

	if (b->wr_pos + reqlen >= b->len)
		rc = buffer_resize(b, b->len + reqlen + BUF_BS);
	return rc;
}

static inline void buffer_append(struct buffer *b, char *data, size_t len)
{
	if (!buffer_alloc(b, len)) {
		memcpy(&b->data[b->wr_pos], data, len);
		b->wr_pos += len;
	}
}

static inline void buffer_consume(struct buffer *b, size_t bytes)
{
	b->rd_pos += bytes;
}

static inline void buffer_dump(struct buffer *b)
{
	fprintf(stderr, "data %p len %zu rd %zu wr %zu\n",
		b->data, b->len, b->rd_pos, b->wr_pos);
}

static inline int buffer_flush(struct buffer *b)
{
	const size_t newlen = b->len - b->rd_pos;
	const size_t newpos = b->wr_pos - b->rd_pos;

	if (b->rd_pos == 0)
		return 0;

	if (newpos) {
		char *new_data = (char *)malloc(newlen);

		if (new_data == NULL)
			return -1;

		memcpy(new_data, &b->data[b->rd_pos], newpos);
		free(b->data);
		b->data = new_data;
	} else {
		b->data = (char *)realloc(b->data, newlen);
	}
	b->len = newlen;
	b->wr_pos = newpos;
	b->rd_pos = 0;
	return 0;
}

static inline void buffer_init(struct buffer *b)
{
	memset(b, 0, sizeof(*b));
}

static inline void buffer_free(struct buffer *b)
{
	free(b->data);
	buffer_init(b);
}

#ifdef __cplusplus
}
#endif

#endif
