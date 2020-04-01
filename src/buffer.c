/*
 * Copyright (c) 2012, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h> /* malloc */
#include <string.h> /* memcpy */
#include <stdint.h> /* uint16_t */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <ev.h>
#include "buffer.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define NOT_POWER_OF_2(x) (x == 0 || (x & (x - 1)))

/* How much extra data to store for SOCK_DGRAM reads */
#define EXTRA_SOCK_DGRAM 2


static const size_t BUFFER_MAX_SIZE = 1024 * 1024 * 1024;


static size_t setup_write_iov(const struct Buffer *, struct iovec *, size_t, size_t *);
static size_t setup_read_iov(const struct Buffer *, struct iovec *, size_t);
static inline void advance_write_position(struct Buffer *, size_t);
static inline void advance_read_position(struct Buffer *, size_t);


struct Buffer *
new_buffer(int type, size_t size, struct ev_loop *loop) {
    if (NOT_POWER_OF_2(size))
        return NULL;
    struct Buffer *buf = malloc(sizeof(struct Buffer));
    if (buf == NULL)
        return NULL;

    buf->type = type;
    buf->size_mask = size - 1;
    buf->len = 0;
    buf->head = 0;
    buf->tx_bytes = 0;
    buf->rx_bytes = 0;
    buf->last_recv = ev_now(loop);
    buf->last_send = ev_now(loop);
    buf->buffer = malloc(size);
    if (buf->buffer == NULL) {
        free(buf);
        buf = NULL;
    }

    return buf;
}

ssize_t
buffer_resize(struct Buffer *buf, size_t new_size) {
    if (NOT_POWER_OF_2(new_size))
        return -4;

    if (new_size > BUFFER_MAX_SIZE)
        return -3;

    if (new_size < buf->len)
        return -1; /* new_size too small to hold existing data */

    char *new_buffer = malloc(new_size);
    if (new_buffer == NULL)
        return -2;

    buffer_peek(buf, new_buffer, new_size);

    free(buf->buffer);
    buf->buffer = new_buffer;
    buf->size_mask = new_size - 1;
    buf->head = 0;

    return (ssize_t)buf->len;
}

void
free_buffer(struct Buffer *buf) {
    if (buf == NULL)
        return;

    free(buf->buffer);
    free(buf);
}

ssize_t
buffer_recv(struct Buffer *buffer, int sockfd, int flags, struct ev_loop *loop) {
    struct msghdr msg = { 0 };

    return buffer_recvmsg(buffer, sockfd, &msg, flags, loop);
}

ssize_t
buffer_recvmsg(struct Buffer *buffer, int sockfd, struct msghdr *msg,
        int flags, struct ev_loop *loop) {
    /* coalesce when reading into an empty buffer */
    if (buffer->len == 0)
        buffer->head = 0;

    struct iovec iov[2];
    size_t start = 0; /* Where to save the size for SOCK_DGRAM sockets */
    msg->msg_iov = iov;
    msg->msg_iovlen = setup_write_iov(buffer, iov, 0, &start);

    ssize_t bytes = recvmsg(sockfd, msg, flags);

    size_t extra_bytes = 0;
    /*
     * If this is a DGRAM socket, save the size as a uint16_t in the first
     * 2 bytes, represented by buffer->head.
     */
    if (buffer->type == SOCK_DGRAM) {
        buffer->buffer[buffer->head+start] = (unsigned char)bytes >> 8;
        buffer->buffer[buffer->head+start+1] = (unsigned char)bytes;
        /* Move past the 2 bytes of UDP length we just wrote */
        extra_bytes = EXTRA_SOCK_DGRAM;
    }

    buffer->last_recv = ev_now(loop);

    if (bytes > 0)
        advance_write_position(buffer, (size_t)bytes+extra_bytes);

    return bytes;
}

ssize_t
buffer_send(struct Buffer *buffer, int sockfd, int flags, struct ev_loop *loop) {
    struct msghdr msg = { 0 };

    return buffer_sendmsg(buffer, sockfd, &msg, flags, loop);
}

ssize_t
buffer_sendmsg(struct Buffer *buffer, int sockfd, struct msghdr *msg, int flags, struct ev_loop *loop) {
    struct iovec iov[2];
    msg->msg_iov = iov;
    msg->msg_iovlen = setup_read_iov(buffer, iov, 0);

    ssize_t bytes = sendmsg(sockfd, msg, flags);

    buffer->last_send = ev_now(loop);

    size_t extra_bytes = 0;
    if (buffer->type == SOCK_DGRAM) {
        /* Move past the 2 bytes of UDP length we just read */
        extra_bytes = EXTRA_SOCK_DGRAM;
    }

    if (bytes > 0)
        advance_read_position(buffer, (size_t)bytes + extra_bytes);

    return bytes;
}

/*
 * Read data from file into buffer
 */
ssize_t
buffer_read(struct Buffer *buffer, int fd) {
    /* coalesce when reading into an empty buffer */
    if (buffer->len == 0)
        buffer->head = 0;

    struct iovec iov[2];
    size_t start = 0;
    size_t iov_len = setup_write_iov(buffer, iov, 0, &start);
    ssize_t bytes = readv(fd, iov, iov_len);

    if (bytes > 0)
        advance_write_position(buffer, (size_t)bytes);

    return bytes;
}

/*
 * Write data to file from buffer
 */
ssize_t
buffer_write(struct Buffer *buffer, int fd) {
    struct iovec iov[2];
    size_t iov_len = setup_read_iov(buffer, iov, 0);
    ssize_t bytes = writev(fd, iov, iov_len);

    if (bytes > 0)
        advance_read_position(buffer, (size_t)bytes);

    return bytes;
}

/*
 * Coalesce a buffer into a single continuous region, optionally returning a
 * pointer to that region.
 *
 * Returns the size of the buffer contents
 */
size_t
buffer_coalesce(struct Buffer *buffer, const void **dst) {
    size_t buffer_tail = (buffer->head + buffer->len) & buffer->size_mask;

    if (buffer_tail <= buffer->head) {
        /* buffer not wrapped */

        if (buffer->type == SOCK_STREAM) {
            if (dst != NULL)
                *dst = &buffer->buffer[buffer->head];

            return buffer->len;
        } else {
            size_t dgram_read = (unsigned char)buffer->buffer[buffer->head] << 8 |
                                (unsigned char)buffer->buffer[buffer->head+1];

            if (dst != NULL)
                *dst = &buffer->buffer[buffer->head+EXTRA_SOCK_DGRAM];

            return dgram_read;
        }
    } else {
        /* buffer wrapped */

        size_t len = buffer->len;
        char *temp = malloc(len);
        if (temp != NULL) {
            buffer_pop(buffer, temp, len);
            assert(buffer->len == 0);

            buffer_push(buffer, temp, len, BUFFER_DGRAM_LENGTH_SKIP);
            assert(buffer->head == 0);
            assert(buffer->len == len);

            free(temp);
        }

        if (buffer->type == SOCK_STREAM) {
            if (dst != NULL)
                *dst = buffer->buffer;

            return buffer->len;
        } else {
            size_t dgram_read = (unsigned char)buffer->buffer[buffer->head] << 8 |
                                (unsigned char)buffer->buffer[buffer->head+1];

            if (dst != NULL)
              *dst = &buffer->buffer[buffer->head+EXTRA_SOCK_DGRAM];

          return dgram_read+EXTRA_SOCK_DGRAM;
        }
    }
}

size_t
buffer_peek(struct Buffer *src, void *dst, size_t len) {
    struct iovec iov[2];
    size_t bytes_copied = 0;

    size_t iov_len = setup_read_iov(src, iov, len);

    for (size_t i = 0; i < iov_len; i++) {
        if (dst != NULL)
            memcpy((char *)dst + bytes_copied, iov[i].iov_base, iov[i].iov_len);

        bytes_copied += iov[i].iov_len;
    }

    return bytes_copied;
}

size_t
buffer_pop(struct Buffer *src, void *dst, size_t len) {
    size_t bytes = 0;

    while (src->len != 0) {
        bytes = buffer_peek(src, dst, len);

        size_t extra_bytes = 0;
        if (src->type == SOCK_DGRAM) {
            /* Move past the 2 bytes of UDP length we just read */
            extra_bytes = EXTRA_SOCK_DGRAM;
        }

        if (bytes > 0)
            advance_read_position(src, bytes+extra_bytes);
    }

    return bytes;
}

size_t
buffer_push(struct Buffer *dst, const void *src, size_t len, int add_length) {
    struct iovec iov[2];
    size_t bytes_appended = 0;

    /* coalesce when reading into an empty buffer */
    if (dst->len == 0)
        dst->head = 0;

    if (buffer_size(dst) - dst->len < len)
        return 0; /* insufficient room */

    size_t start;
    size_t iov_len = setup_write_iov(dst, iov, len, &start);

    size_t extra_bytes = 0;
    /*
     * If this is a DGRAM socket, save the size as a uint16_t in the first
     * 2 bytes, represented by buffer->head.
     */
    if (dst->type == SOCK_DGRAM && add_length == BUFFER_DGRAM_LENGTH_ADD) {
        dst->buffer[dst->head+start] = (unsigned char)len >> 8;
        dst->buffer[dst->head+start+1] = (unsigned char)len;
        /* Move past the 2 bytes of UDP length we just wrote */
        extra_bytes = EXTRA_SOCK_DGRAM;
    }

    for (size_t i = 0; i < iov_len; i++) {
        memcpy(iov[i].iov_base, (char *)src + bytes_appended, iov[i].iov_len);
        bytes_appended += iov[i].iov_len;
    }

    if (bytes_appended > 0)
        advance_write_position(dst, bytes_appended+extra_bytes);

    return bytes_appended;
}

/*
 * Setup a struct iovec iov[2] for a write to a buffer.
 * struct iovec *iov MUST be at least length 2.
 * returns the number of entries setup
 */
static size_t
setup_write_iov(const struct Buffer *buffer, struct iovec *iov, size_t len, size_t *start) {
    size_t room = buffer_size(buffer) - buffer->len;

    if (room == 0) /* trivial case: no room */
        return 0;

    if (start == NULL)
        return 0;

    size_t write_len = room;
    /* Allow caller to specify maximum length */
    if (len != 0)
        write_len = MIN(room, len);

    size_t extra = 0;

    /* Save some room for UDP length for SOCK_DGRAM buffers */
    if (buffer->type == SOCK_DGRAM) {
        /* Save room for UDP packet length */
        extra += EXTRA_SOCK_DGRAM;
    }

    *start = (buffer->head + buffer->len + extra) & buffer->size_mask;

    if (*start + write_len <= buffer_size(buffer)) {
        iov[0].iov_base = buffer->buffer + *start;
        iov[0].iov_len = write_len;

        /* assert iov are within bounds, non-zero length and non-overlapping */
        assert(iov[0].iov_len > 0);
        assert((char *)iov[0].iov_base >= buffer->buffer);
        assert((char *)iov[0].iov_base + iov[0].iov_len <= buffer->buffer + buffer_size(buffer));

        /* For SOCK_DGRAM, remove the 2 bytes of the length so we write into the correct spot */
        *start -= extra;
        return 1;
    } else {
        iov[0].iov_base = buffer->buffer + *start;
        iov[0].iov_len = buffer_size(buffer) - *start;
        iov[1].iov_base = buffer->buffer;
        iov[1].iov_len = write_len - iov[0].iov_len;

        /* assert iov are within bounds, non-zero length and non-overlapping */
        assert(iov[0].iov_len > 0);
        assert((char *)iov[0].iov_base >= buffer->buffer);
        assert((char *)iov[0].iov_base + iov[0].iov_len <= buffer->buffer + buffer_size(buffer));
        assert(iov[1].iov_len > 0);
        assert((char *)iov[1].iov_base >= buffer->buffer);
        assert((char *)iov[1].iov_base + iov[1].iov_len <= (char *)iov[0].iov_base);

        /* For SOCK_DGRAM, remove the 2 bytes of the length so we write into the correct spot */
        *start -= extra;
        return 2;
    }
}

static size_t
setup_read_iov(const struct Buffer *buffer, struct iovec *iov, size_t len) {
    if (buffer->len == 0)
        return 0;

    size_t read_len = buffer->len;
    size_t extra_bytes = 0;
    if (buffer->type == SOCK_STREAM) {
        if (len != 0)
            read_len = MIN(len, buffer->len);
    }

    else { /* SOCK_DGRAM */
        size_t dgram_read = (unsigned char)buffer->buffer[buffer->head] << 8 |
                            (unsigned char)buffer->buffer[buffer->head+1];
        extra_bytes = EXTRA_SOCK_DGRAM;
        read_len = dgram_read;

        if (len != 0)
            read_len = MIN(len, read_len);
    }

    if (buffer->head + read_len <= buffer_size(buffer)) {
        iov[0].iov_base = buffer->buffer + buffer->head + extra_bytes;
        iov[0].iov_len = read_len;

        /* assert iov are within bounds, non-zero length and non-overlapping */
        assert(iov[0].iov_len > 0);
        assert((char *)iov[0].iov_base >= buffer->buffer);
        assert((char *)iov[0].iov_base + iov[0].iov_len <= buffer->buffer + buffer_size(buffer));

        return 1;
    } else {
        iov[0].iov_base = buffer->buffer + buffer->head + extra_bytes;
        iov[0].iov_len = buffer_size(buffer) - buffer->head;
        iov[1].iov_base = buffer->buffer;
        iov[1].iov_len = read_len - iov[0].iov_len;

        /* assert iov are within bounds, non-zero length and non-overlapping */
        assert(iov[0].iov_len > 0);
        assert((char *)iov[0].iov_base >= buffer->buffer);
        assert((char *)iov[0].iov_base + iov[0].iov_len <= buffer->buffer + buffer_size(buffer));
        assert(iov[1].iov_len > 0);
        assert((char *)iov[1].iov_base >= buffer->buffer);
        assert((char *)iov[1].iov_base + iov[1].iov_len <= (char *)iov[0].iov_base);

        return 2;
    }
}

static inline void
advance_write_position(struct Buffer *buffer, size_t offset) {
    buffer->len += offset;
    buffer->rx_bytes += offset;
}

static inline void
advance_read_position(struct Buffer *buffer, size_t offset) {
    buffer->head = (buffer->head + offset) & buffer->size_mask;
    buffer->len -= offset;
    buffer->tx_bytes += offset;
}
