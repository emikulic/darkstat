/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * localip.c: determine local IP of our capture interface
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "addr.h"
#include "config.h" /* for HAVE_IFADDRS_H */
#include "err.h"
#include "localip.h"
#include "bsd.h" /* for strlcpy */

#include <sys/socket.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#else
# ifdef HAVE_SYS_SOCKIO_H
#  include <sys/sockio.h> /* for SIOCGIFADDR, especially on Solaris */
# endif
# include <sys/ioctl.h>
#endif

static const char *iface = NULL;
struct addr localip4, localip6;
static struct addr last_localip4, last_localip6;

void
localip_init(const char *interface)
{
   iface = interface;

   /* defaults */
   localip4.family = IPv4;
   localip4.ip.v4 = 0;

   localip6.family = IPv6;
   memset(&(localip6.ip.v6), 0, sizeof(localip6.ip.v6));

   last_localip4 = localip4;
   last_localip6 = localip6;

   /* initial update */
   localip_update();
}

static void
localip_update_helper(void)
{
   /* defaults */
   localip4.family = IPv4;
   localip4.ip.v4 = 0;

   localip6.family = IPv6;
   memset(&(localip6.ip.v6), 0, sizeof(localip6.ip.v6));

   if (iface == NULL)
      return; /* reading from capfile */

#ifdef HAVE_IFADDRS_H
   {
      int got_v4 = 0, got_v6 = 0;
      struct ifaddrs *ifas, *ifa;

      if (getifaddrs(&ifas) < 0) {
         warn("can't getifaddrs() on interface \"%s\"", iface);
         return;
      }

      for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
         if (got_v4 && got_v6)
            break;   /* Task is already complete. */

         if (strncmp(ifa->ifa_name, iface, IFNAMSIZ))
            continue;   /* Wrong interface. */

         if (!ifa->ifa_addr)
            continue;   /* This can be NULL, e.g. for ppp0. */

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

      if (!got_v4)
          warnx("can't get own IPv4 address on interface \"%s\"", iface);
   }
#else /* don't HAVE_IFADDRS_H */
   {
      int tmp = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
      struct ifreq ifr;
      struct sockaddr sa;

      strlcpy(ifr.ifr_name, iface, IFNAMSIZ);
      ifr.ifr_addr.sa_family = AF_INET;
      if (ioctl(tmp, SIOCGIFADDR, &ifr) == -1) {
         if (errno == EADDRNOTAVAIL) {
            verbosef("lost local IP");
         } else
            warn("can't get own IP address on interface \"%s\"", iface);
      } else {
         /* success! */
         sa = ifr.ifr_addr;
         localip4.ip.v4 = ((struct sockaddr_in*)&sa)->sin_addr.s_addr;
      }
      close(tmp);
   }
#endif
}

void
localip_update(void)
{
   localip_update_helper();

   if (!addr_equal(&last_localip4, &localip4)) {
      verbosef("%s ip4 update: %s", iface, addr_to_str(&localip4));
      last_localip4 = localip4;
   }
   if (!addr_equal(&last_localip6, &localip6)) {
      verbosef("%s ip6 update: %s", iface, addr_to_str(&localip6));
      last_localip6 = localip6;
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
