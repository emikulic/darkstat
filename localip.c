/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
 *
 * localip.c: determine local IP of our capture interface
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "darkstat.h"
#include "conv.h" /* for strlcpy */
#include "decode.h" /* for ip_to_str, ip6_to_str */
#include "err.h"
#include "localip.h"

#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static const char *iface = NULL;

in_addr_t localip = 0;
static in_addr_t last_localip = 0;

struct in6_addr localip6;
static struct in6_addr last_localip6;

void
localip_init(const char *interface)
{
   iface = interface;
   localip_update();
}

void
localip_update(void)
{
   struct ifaddrs *ifas, *ifa;
   int flags = 0;

#define HAS_IPV4  0x01
#define HAS_IPV6  0x02

   if (iface == NULL) {
      /* reading from capfile */
      localip = 0;
      memset(&localip6, '\0', sizeof(localip6));
      return;
   }

   if (getifaddrs(&ifas) < 0)
      err(1, "can't get own IP address on interface \"%s\"", iface);

   for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
      if (flags == (HAS_IPV4 | HAS_IPV6))
         break;   /* Task is already complete. */

      if (strncmp(ifa->ifa_name, iface, IFNAMSIZ))
         continue;   /* Wrong interface. */

      /* The first IPv4 name is always functional. */
      if ( (ifa->ifa_addr->sa_family == AF_INET)
            && ! (flags & HAS_IPV4) ) {
         /* Good IPv4 address. */
         localip = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr;
         flags |= HAS_IPV4;
         continue;
      }

      /* IPv6 needs some obvious exceptions. */
      if( ifa->ifa_addr->sa_family == AF_INET6 ) {
         struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) ifa->ifa_addr;

#ifdef __FreeBSD__
         if( IN6_IS_ADDR_LINKLOCAL(&(sa6->sin6_addr))
            || IN6_IS_ADDR_SITELOCAL(&(sa6->sin6_addr)) )
#else
         if( IN6_IS_ADDR_LINKLOCAL(&(sa6->sin6_addr.s6_addr))
            || IN6_IS_ADDR_SITELOCAL(&(sa6->sin6_addr.s6_addr)) )
#endif
            continue;
         else
            /* Only standard IPv6 can reach this point. */
            memcpy(&localip6, &sa6->sin6_addr, sizeof(localip6));
            flags |= HAS_IPV6;
      }
   }

   freeifaddrs(ifas);

   /* Repport an error if IPv4 address could not be found. */
   if ( !(flags & HAS_IPV4) )
       err(1, "can't get own IPv4 address on interface \"%s\"", iface);

   /* struct sockaddr {
    *      sa_family_t     sa_family;      * address family, AF_xxx
    *      char            sa_data[14];    * 14 bytes of protocol address
    *
    * struct sockaddr_in {
    *      sa_family_t           sin_family;     * Address family
    *      unsigned short int    sin_port;       * Port number
    *      struct in_addr        sin_addr;       * Internet address
    *
    * struct in_addr {
    *      __u32   s_addr;
    */

   if (last_localip != localip) {
      verbosef("local_ip update(%s) = %s", iface, ip_to_str(localip));
      last_localip = localip;
   }
   if (memcmp(&last_localip6, &localip6, sizeof(localip6))) {
      verbosef("local_ip6 update(%s) = %s", iface, ip6_to_str(&localip6));
      memcpy(&last_localip6, &localip6, sizeof(localip6));
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
