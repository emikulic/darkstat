/* darkstat 3
 * copyright (c) 2011 Emil Mikulic.
 *
 * addr.c: compound IPv4/IPv6 address
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "addr.h"

#include <assert.h>
#include <string.h> /* for memcmp */

int addr_equal(const struct addr * const a, const struct addr * const b)
{
   if (a->family != b->family)
      return 0;
   if (a->family == IPv4)
      return (a->ip.v4 == b->ip.v4);
   else {
      assert(a->family == IPv6);
      return (memcmp(&(a->ip.v6), &(b->ip.v6), sizeof(a->ip.v6)) == 0);
   }
}

static char _addrstrbuf[INET6_ADDRSTRLEN];
const char *addr_to_str(const struct addr * const a)
{
   if (a->family == IPv4) {
      struct in_addr in;
      in.s_addr = a->ip.v4;
      return (inet_ntoa(in));
   } else {
      assert(a->family == IPv6);
      inet_ntop(AF_INET6, &(a->ip.v6), _addrstrbuf, sizeof(_addrstrbuf));
      return (_addrstrbuf);
   }
}

/* vim:set ts=3 sw=3 tw=78 et: */
