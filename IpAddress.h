/* Copyright (c) 2010-2015 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef RAMCLOUD_IPADDRESS_H
#define RAMCLOUD_IPADDRESS_H

#include <netinet/in.h>

/**
 * This class translates between ServiceLocators and IP sockaddr structs,
 * providing a standard mechanism for use in Transport and Driver classes.
 */
class IpAddress {
  public:
    IpAddress() : address() {}

    IpAddress(const char* hostName, uint16_t port);
    IpAddress(uint32_t ip, uint16_t port);

    IpAddress(const IpAddress& other)
        : address(other.address) {}

    sockaddr address;
};

#endif  // RAMCLOUD_IPADDRESS_H
