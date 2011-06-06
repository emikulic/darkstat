/* darkstat 3
 * copyright (c) 2011 Emil Mikulic.
 *
 * addr.h: compound IPv4/IPv6 address
 * (because struct sockaddr_storage stores too much)
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */
#ifndef __DARKSTAT_ADDR_H
#define __DARKSTAT_ADDR_H

#include <sys/types.h> /* for in_addr_t, at least on OpenBSD */
#include <sys/socket.h> /* for AF_INET6 */
#include <netinet/in.h> /* for in6_addr */

struct addr {
   union {
      in_addr_t v4;
      struct in6_addr v6;
   } ip;
   enum { IPv4 = 4, IPv6 = 6 } family;
};

int addr_equal(const struct addr * const a, const struct addr * const b);
const char *addr_to_str(const struct addr * const a);
void addr_mask(struct addr *a, const struct addr * const mask);
int addr_inside(const struct addr * const a,
   const struct addr * const net, const struct addr * const mask);

/* Returns 0 on success, gai_strerror() code otherwise. */
int str_to_addr(const char *s, struct addr *a);

#endif
/* vim:set ts=3 sw=3 tw=78 et: */
