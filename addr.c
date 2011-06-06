/* darkstat 3
 * copyright (c) 2011 Emil Mikulic.
 *
 * addr.c: compound IPv4/IPv6 address
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "addr.h"

#include <arpa/inet.h> /* for inet_ntop */
#include <assert.h>
#include <string.h> /* for memcmp */
#include <netdb.h> /* for getaddrinfo */

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

int str_to_addr(const char *s, struct addr *a)
{
   struct addrinfo hints, *ai;
   int ret;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_flags = AI_NUMERICHOST;

   if ((ret = getaddrinfo(s, NULL, &hints, &ai)) != 0)
      return (ret);

   if (ai->ai_family == AF_INET) {
      a->family = IPv4;
      a->ip.v4 = ((const struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
   } else if (ai->ai_family == AF_INET6) {
      a->family = IPv6;
      memcpy(&(a->ip.v6),
             ((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr.s6_addr,
             sizeof(a->ip.v6));
   } else {
      ret = EAI_FAMILY;
   }

   freeaddrinfo(ai);
   return (ret);
}

void addr_mask(struct addr *a, const struct addr * const mask)
{
   assert(a->family == mask->family);
   if (a->family == IPv4)
      a->ip.v4 &= mask->ip.v4;
   else {
      size_t i;

      assert(a->family == IPv6);
      for (i=0; i<sizeof(a->ip.v6.s6_addr); i++)
         a->ip.v6.s6_addr[i] &= mask->ip.v6.s6_addr[i];
   }
}

int addr_inside(const struct addr * const a,
   const struct addr * const net, const struct addr * const mask)
{
   struct addr masked;

   assert(a->family == net->family);
   assert(a->family == mask->family);

   masked = *a;
   addr_mask(&masked, mask);
   return (addr_equal(&masked, net));
}

/* vim:set ts=3 sw=3 tw=78 et: */
