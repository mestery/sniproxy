#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ev.h>
#include "buffer.h"

static void test1() {
    struct Buffer *buffer;
    char input[] = "This is a test.";
    char output[sizeof(input)];
    int len, i;

    buffer = new_buffer(SOCK_STREAM, 256, EV_DEFAULT);
    assert(buffer != NULL);

    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    /* second peek to ensure the first didn't permute the state of the buffer */
    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    /* test pop */
    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == 0);

    free_buffer(buffer);
}

static void test2() {
    struct Buffer *buffer;
    char input[] = "Testing wrap around behaviour.";
    char output[sizeof(input)];
    int len, i = 0;

    buffer = new_buffer(SOCK_STREAM, 256, EV_DEFAULT);
    assert(buffer != NULL);

    while (i < 236) {
        len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
        assert(len == sizeof(input));

        i += len;
    }

    while (len) {
        len = buffer_pop(buffer, output, sizeof(output));
    }

    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    free_buffer(buffer);
}

static void test3() {
    struct Buffer *buffer;
    char input[] = "Test buffer resizing.";
    char output[sizeof(input)];
    int len, i;

    buffer = new_buffer(SOCK_STREAM, 256, EV_DEFAULT);
    assert(buffer != NULL);

    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));

    /* Test resizing to too small of a buffer size */
    len = buffer_resize(buffer, 8);
    assert(len == -1);


    buffer_resize(buffer, 32);
    assert(buffer_room(buffer) == 32 - sizeof(input));

    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    free_buffer(buffer);
}

static void test4() {
    struct Buffer *buffer;
    int read_fd, write_fd;

    buffer = new_buffer(SOCK_STREAM, 4096, EV_DEFAULT);

    read_fd = open("/dev/zero", O_RDONLY);
    if (read_fd < 0) {
        perror("open:");
        exit(1);
    }

    write_fd = open("/dev/null", O_WRONLY);
    if (write_fd < 0) {
        perror("open:");
        exit(1);
    }

    while (buffer->tx_bytes < 65536) {
        buffer_read(buffer, read_fd);
        buffer_write(buffer, write_fd);
    }

    free_buffer(buffer);
}

static void test_buffer_coalesce() {
    struct Buffer *buffer;
    char input[] = "Test buffer resizing.";
    char output[sizeof(input)];
    int len;

    buffer = new_buffer(SOCK_STREAM, 4096, EV_DEFAULT);
    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(output));
    assert(buffer_len(buffer) == 0);
    assert(buffer->head != 0);

    len = buffer_coalesce(buffer, NULL);
    assert(len == 0);
}

static void test5_udp1() {
    struct Buffer *buffer;
    //char input[] = "This is a UDP test.";
    unsigned char input[] = { 0x00, 0x13,
                              0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
                              0x61, 0x20, 0x55, 0x44, 0x50, 0x20, 0x74, 0x65,
                              0x73, 0x74, 0x2e };
    char output[sizeof(input)];
    int len, i;

    buffer = new_buffer(SOCK_DGRAM, 256, EV_DEFAULT);
    assert(buffer != NULL);

    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    /* second peek to ensure the first didn't permute the state of the buffer */
    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    /* test pop */
    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == 0);

    free_buffer(buffer);
}

static void test6_udp2() {
    struct Buffer *buffer;
    //char input[] = "Testing wrap around behaviour.";
    unsigned char input[] = { 0x00, 0x1f,
                              0x54, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x20,
                              0x77, 0x72, 0x61, 0x70, 0x20, 0x61, 0x72, 0x6f,
                              0x75, 0x6e, 0x64, 0x20, 0x62, 0x65, 0x68, 0x61,
                              0x76, 0x69, 0x6f, 0x75, 0x72, 0x2e, 0x0d };
    char output[sizeof(input)];
    int len, i = 0;

    buffer = new_buffer(SOCK_DGRAM, 256, EV_DEFAULT);
    assert(buffer != NULL);

    while (i < 231) {
        len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
        assert(len == sizeof(input));

        i += len;
    }

    while (len) {
        len = buffer_pop(buffer, output, sizeof(output));
    }

    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    free_buffer(buffer);
}

static void test_buffer_coalesce_udp() {
    struct Buffer *buffer;
    //char input[] = "Test buffer resizing.";
    unsigned char input[] = { 0x00, 0x15,
                              0x54, 0x65, 0x73, 0x74, 0x20, 0x62, 0x75, 0x66,
                              0x66, 0x65, 0x72, 0x20, 0x72, 0x65, 0x73, 0x69,
                              0x7a, 0x69, 0x6e, 0x67, 0x2e };
    unsigned char output[sizeof(input)];
    int len;

    buffer = new_buffer(SOCK_DGRAM, 4096, EV_DEFAULT);
    len = buffer_push(buffer, input, sizeof(input), BUFFER_DGRAM_LENGTH_ADD);
    assert(len == sizeof(input));

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(output));
    assert(buffer_len(buffer) == 0);
    assert(buffer->head != 0);

    len = buffer_coalesce(buffer, NULL);
    assert(len == 0);
}

int main() {
    test1();

    test2();

    test3();

    test4();

    test_buffer_coalesce();

    test5_udp1();

    test6_udp2();

    test_buffer_coalesce_udp();
}
