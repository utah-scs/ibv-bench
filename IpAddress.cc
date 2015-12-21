/* Copyright (c) 2010-2015 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "Common.h"
#include "IpAddress.h"

#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <string.h>

#include <string>

/**
 * Construct an IpAddress from the information in a ServiceLocator.
 * \param serviceLocator
 *      The "host" and "port" options describe the desired address.
 * \throw BadIpAddress
 *      The serviceLocator couldn't be converted to an IpAddress
 *      (e.g. a required option was missing, or the host name
 *      couldn't be parsed).
 */
IpAddress::IpAddress(const char* hostName, uint16_t port)
    : address()
{
    hostent host;
    hostent* result;
    char buffer[4096];
    int error;
    sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&address);
    addr->sin_family = AF_INET;

    // Warning! The return value from getthostbyname_r is advertised
    // as being the same as what is returned at error, but it is not;
    // don't use it.
    gethostbyname_r(hostName, &host, buffer, sizeof(buffer),
            &result, &error);
    if (result == 0) {
        // If buffer is too small, an error value of ERANGE is supposed
        // to be returned, but in fact it appears that error is -1 in
        // the situation; check for both.
        if ((error == ERANGE) || (error == -1)) {
            DIE("IpAddress::IpAddress called gethostbyname_r "
                    "with too small a buffer");
        }
        DIE("couldn't find host '%s'", hostName);
    }
    memcpy(&addr->sin_addr, host.h_addr, sizeof(addr->sin_addr));
    addr->sin_port = htons(port);
}

/**
 * Construct an IpAddress from the two input arguments ip and port.
 * This only works for ip4 version.
 * \param ip
 *      the ip version 4 address for the host. This must be constructed
 *      by putting to gether the 4 bytes of the ip in host order.
 * \param port
 *      the ip port for the host. This must be constructed
 *      by putting to gether the 2 bytes of the port in host order.
 */
IpAddress::IpAddress(uint32_t ip, uint16_t port)
    :address()
{
    sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&address);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(ip);
    addr->sin_port = ntohs(port);
}
