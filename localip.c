/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * localip.c: determine local IP of our capture interface
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "addr.h"
#include "conv.h" /* for strlcpy */
#include "err.h"
#include "localip.h"

#include <sys/types.h> /* OpenBSD needs this */
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static const char *iface = NULL;
struct addr localip4, localip6;
static struct addr last_localip4, last_localip6;

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
   int got_v4 = 0, got_v6 = 0;

   localip4.family = IPv4;
   localip6.family = IPv6;

   if (iface == NULL) {
      /* reading from capfile */
      localip4.ip.v4 = 0;
      memset(&(localip6.ip.v6), 0, sizeof(localip6.ip.v6));
      return;
   }

   if (getifaddrs(&ifas) < 0)
      err(1, "can't get own IP address on interface \"%s\"", iface);

   for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
      if (got_v4 && got_v6)
         break;   /* Task is already complete. */

      if (strncmp(ifa->ifa_name, iface, IFNAMSIZ))
         continue;   /* Wrong interface. */

      /* The first IPv4 name is always functional. */
      if ((ifa->ifa_addr->sa_family == AF_INET) && !got_v4)
      {
         /* Good IPv4 address. */
         localip4.ip.v4 =
            ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
         got_v4 = 1;
         continue;
      }

      /* IPv6 needs some obvious exceptions. */
      if ( ifa->ifa_addr->sa_family == AF_INET6 ) {
         struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) ifa->ifa_addr;

         if ( IN6_IS_ADDR_LINKLOCAL(&(sa6->sin6_addr))
              || IN6_IS_ADDR_SITELOCAL(&(sa6->sin6_addr)) )
            continue;

         /* Only standard IPv6 can reach this point. */
         memcpy(&(localip6.ip.v6), &sa6->sin6_addr, sizeof(localip6.ip.v6));
         got_v6 = 1;
      }
   }

   freeifaddrs(ifas);

   /* Report an error if IPv4 address could not be found. */
   if (!got_v4)
       err(1, "can't get own IPv4 address on interface \"%s\"", iface);

   if (!addr_equal(&last_localip4, &localip4)) {
      verbosef("localip4 update(%s) = %s", iface, addr_to_str(&localip4));
      last_localip4 = localip4;
   }
   if (!addr_equal(&last_localip6, &localip6)) {
      verbosef("localip6 update(%s) = %s", iface, addr_to_str(&localip6));
      last_localip6 = localip6;
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
