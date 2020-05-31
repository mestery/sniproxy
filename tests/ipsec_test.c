/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 *
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "ipsec.h"

struct test_packet {
    const char *packet;
    size_t len;
    const char *hostname;
};

const char good_hostname_1[] = "notapplicable";
const unsigned char good_data_1[] = {
    // Zero length SPI means this is an IKEv2 packet
    0x00, 0x00, 0x00, 0x00,
    // Initiator SPI
    0xe5, 0xbc, 0x67, 0x55, 0x0f, 0xd4, 0xd3, 0xea,
    // Responder SPI
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Next payload: SA
    0x21,
    // Version
    0x20,
    // Exchange type: IKE_SA_INIT
    0x22,
    // Flags: (Initiator, no higher version, request)
    0x08,
    // Message ID
    0x00, 0x00, 0x00, 0x00,
    // Length (216 bytes)
    0xad, 0x92,
    // We can ignore the rest ...
};

const unsigned char bad_data_1[] = {
    // Zero length SPI means this is an IKEv2 packet
    0x00, 0x00, 0x00, 0x00,
    // Initiator SPI
    0xe5, 0xbc, 0x67, 0x55, 0x0f, 0xd4, 0xd3, 0xea,
    // Responder SPI
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Next payload: *** INVALID
    0x41,
    // Version
    0x20,
    // Exchange type: IKE_SA_INIT
    0x22,
    // Flags: (Initiator, no higher version, request)
    0x08,
    // Message ID
    0x00, 0x00, 0x00, 0x00,
    // Length (216 bytes)
    0xad, 0x92,
    // We can ignore the rest ...
};

const unsigned char bad_data_2[] = {
    // Zero length SPI means this is an IKEv2 packet
    0x00, 0x00, 0x00, 0x00,
    // Initiator SPI
    0xe5, 0xbc, 0x67, 0x55, 0x0f, 0xd4, 0xd3, 0xea,
    // Responder SPI
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Next payload: SA
    0x21,
    // Version *** INVALID
    0x10,
    // Exchange type: IKE_SA_INIT
    0x22,
    // Flags: (Initiator, no higher version, request)
    0x08,
    // Message ID
    0x00, 0x00, 0x00, 0x00,
    // Length (216 bytes)
    0xad, 0x92,
    // We can ignore the rest ...
};

const unsigned char bad_data_3[] = {
    // Zero length SPI means this is an IKEv2 packet
    0x00, 0x00, 0x00, 0x00,
    // Initiator SPI
    0xe5, 0xbc, 0x67, 0x55, 0x0f, 0xd4, 0xd3, 0xea,
    // Responder SPI
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Next payload: SA
    0x21,
    // Version
    0x20,
    // Exchange type: *** INVALID
    0x02,
    // Flags: (Initiator, no higher version, request)
    0x08,
    // Message ID
    0x00, 0x00, 0x00, 0x00,
    // Length (216 bytes)
    0xad, 0x92,
    // We can ignore the rest ...
};

static struct test_packet good[] = {
    { (char *)good_data_1, sizeof(good_data_1), good_hostname_1 },
};

static struct test_packet bad[] = {
    { (char *)bad_data_1, sizeof(bad_data_1), NULL },
    { (char *)bad_data_2, sizeof(bad_data_2), NULL },
    { (char *)bad_data_3, sizeof(bad_data_3), NULL }
};

int main() {
    unsigned int i;
    int result;
    char *hostname;

    for (i = 0; i < sizeof(good) / sizeof(struct test_packet); i++) {
        hostname = NULL;

        printf("Testing packet of length %zu\n", good[i].len);
        result = ipsec_protocol->parse_packet(good[i].packet, good[i].len, &hostname);

        assert(result == 13);

        assert(NULL != hostname);

        assert(0 == strcmp(good[i].hostname, hostname));

    }

    for (i = 0; i < sizeof(bad) / sizeof(struct test_packet); i++) {
        hostname = NULL;

        result = ipsec_protocol->parse_packet(bad[i].packet, bad[i].len, &hostname);

        // parse failure or not "localhost"
        if (bad[i].hostname != NULL)
            assert(result < 0 ||
                   hostname == NULL);

        free(hostname);
    }

}
