#ifndef _BUFFER_H
#define _BUFFER_H

#include <stdint.h>
#include <stddef.h>

typedef struct buffer {
    int off;
    int size; // for TCP packet
    size_t capacity;
    size_t len;
    uint8_t *data;
} buffer_t;

int buffer_alloc(buffer_t *ptr, size_t capacity);
int buffer_realloc(buffer_t *buf, size_t len, size_t capacity);
void buffer_free(buffer_t *buf);
void buffer_reset(buffer_t *buf);

#endif // for #ifndef _BUFFER_H
