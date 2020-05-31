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
/*
 * This is a minimal IKEv2 packet parser.
 */

#include <stdio.h>
#include <stdlib.h> /* malloc() */
#include <stdint.h>
#include <string.h> /* strncpy() */
#include <sys/socket.h>
#include <sys/types.h>
#include "ipsec.h"
#include "sni.h"
#include "protocol.h"
#include "logger.h"

#define IPSEC_HEADER_LEN     4
#define IKEV2_HEADER_LEN     26
#define IKEV2_SA             0x21
#define IKEV2_VERSION        0x20
#define IKEV2_SA_INIT        0x22

static int parse_ipsec_header(const uint8_t*, size_t, char **);

const struct Protocol *const ipsec_protocol = &(struct Protocol){
    .name = "ipsec",
    .default_port = 500,
    .parse_packet = (int (*const)(const char *, size_t, char **))&parse_ipsec_header,
    .abort_message = NULL,
    .abort_message_len = 0,
    .sock_type = SOCK_DGRAM,
};

/* Parse a DTLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  0    - Successfully parsed IKEv2 packet
 *  -1   - Incomplete request
 *  -2   - Incorrect IKE version
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid IPsec IKEv2 payload
 */
static int
parse_ipsec_header(const uint8_t *data, size_t data_len, char **hostname) {
    size_t pos = 0;
    uint8_t spi1, spi2, spi3, spi4;
    uint8_t next_payload;
    uint8_t version;
    uint8_t exchange_type;

    if (hostname == NULL)
        return -3;

    /* Verify header length (e.g. the SPI value) */
    if (data_len < IPSEC_HEADER_LEN)
        return -1;

    /* Get SPI bytes */
    spi1 = data[pos++];
    spi2 = data[pos++];
    spi3 = data[pos++];
    spi4 = data[pos++];

    /* Is this an ESP in UDP packet? */
    if (!(spi1 == 0 && spi2 == 0 && spi3 == 0 && spi4 == 0)) {
        return 0;
    }

    /* Check that our UDP payload is at least large enough for a DTLS header */
    if (data_len < IKEV2_HEADER_LEN)
        return -1;

    /* Skip past the SPI values, 16 bytes in total */
    pos += 16;

    /* Validate next payload is IKEV2_SA */
    next_payload = data[pos];
    if (next_payload != IKEV2_SA)
        return -4;
    pos += 1;

    /* Validate version */
    version = data[pos];
    if (version != IKEV2_VERSION)
        return -4;
    pos += 1;

    /* Validate exchange type */
    exchange_type = data[pos];
    if (exchange_type != IKEV2_SA_INIT)
        return -4;
    pos += 1;

    /* Skip flags */
    pos += 1;

    /* Skip message ID */
    pos += 4;

    /* Skip length */
    pos += 2;

    return 0;
}
