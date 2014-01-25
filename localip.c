/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
 *
 * localip.c: determine local IPs of an interface
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "addr.h"
#include "bsd.h" /* for strlcpy */
#include "config.h" /* for HAVE_IFADDRS_H */
#include "conv.h"
#include "err.h"
#include "localip.h"
#include "now.h"

#include <sys/socket.h>
#include <net/if.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#else
# ifdef HAVE_SYS_SOCKIO_H
#  include <sys/sockio.h> /* for SIOCGIFADDR, especially on Solaris */
# endif
# include <sys/ioctl.h>
#endif

void localip_init(struct local_ips *ips) {
   ips->is_valid = 0;
   ips->last_update_mono = 0;
   ips->num_addrs = 0;
   ips->addrs = NULL;
}

void localip_free(struct local_ips *ips) {
   if (ips->addrs != NULL)
      free(ips->addrs);
}

static void add_ip(const char *iface,
                   struct local_ips *ips,
                   int *idx,
                   struct addr *a) {
   if (ips->num_addrs <= *idx) {
      /* Grow. */
      ips->addrs = xrealloc(ips->addrs, sizeof(*(ips->addrs)) * (*idx + 1));
      ips->num_addrs++;
      assert(ips->num_addrs > *idx);
      verbosef("interface '%s' gained new address %s", iface, addr_to_str(a));
   } else {
      /* Warn about changed address. */
      if (!addr_equal(ips->addrs + *idx, a)) {
         static char before[INET6_ADDRSTRLEN];
         strncpy(before, addr_to_str(ips->addrs + *idx), INET6_ADDRSTRLEN);
         verbosef("interface '%s' address %d/%d changed from %s to %s",
            iface, *idx+1, ips->num_addrs, before, addr_to_str(a));
      }
   }
   ips->addrs[*idx] = *a;
   (*idx)++;
}

/* Returns 0 on failure. */
void localip_update(const char *iface, struct local_ips *ips) {
   struct addr a;
   int new_addrs = 0;

   if (iface == NULL) {
      /* reading from capfile */
      ips->is_valid = 0;
      return;
   }

   if (ips->last_update_mono == now_mono()) {
      /* Too soon, bail out. */
      return;
   }
   ips->last_update_mono = now_mono();

#ifdef HAVE_IFADDRS_H
   {
      struct ifaddrs *ifas, *ifa;

      if (getifaddrs(&ifas) < 0)
         err(1, "getifaddrs() failed");

      for (ifa=ifas; ifa; ifa=ifa->ifa_next) {
         if (strncmp(ifa->ifa_name, iface, IFNAMSIZ))
            continue;   /* Wrong interface. */

         if (!ifa->ifa_addr)
            continue;   /* This can be NULL, e.g. for ppp0. */

         if (ifa->ifa_addr->sa_family == AF_INET) {
            a.family = IPv4;
            a.ip.v4 = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            add_ip(iface, ips, &new_addrs, &a);
         }
         if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
# if 0
            if ( IN6_IS_ADDR_LINKLOCAL(&(sa6->sin6_addr))
                 || IN6_IS_ADDR_SITELOCAL(&(sa6->sin6_addr)) )
               continue;
# endif
            a.family = IPv6;
            memcpy(&(a.ip.v6), &sa6->sin6_addr, sizeof(a.ip.v6));
            add_ip(iface, ips, &new_addrs, &a);
         }
      }
      freeifaddrs(ifas);
   }
#else /* don't HAVE_IFADDRS_H */
   {
      int tmp = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
      struct ifreq ifr;
      struct sockaddr sa;

      strlcpy(ifr.ifr_name, iface, IFNAMSIZ);
      ifr.ifr_addr.sa_family = AF_INET;
      if (ioctl(tmp, SIOCGIFADDR, &ifr) != -1) {
         sa = ifr.ifr_addr;
         a.family = IPv4;
         a.ip.v4 = ((struct sockaddr_in*)(&ifr.ifr_addr))->sin_addr.s_addr;
         add_ip(iface, ips, &new_addrs, &a);
      }
      close(tmp);
   }
#endif
   if (new_addrs == 0) {
      if (ips->is_valid)
         verbosef("interface '%s' no longer has any addresses", iface);
      ips->is_valid = 0;
   } else {
      if (!ips->is_valid)
         verbosef("interface '%s' now has addresses", iface);
      ips->is_valid = 1;
      if (ips->num_addrs != new_addrs)
         verbosef("interface '%s' number of addresses decreased from %d to %d",
            iface, ips->num_addrs, new_addrs);
      ips->num_addrs = new_addrs;
   }
}

int is_localip(const struct addr * const a,
               const struct local_ips * const ips) {
   int i;

   for (i=0; i<ips->num_addrs; i++) {
      if (addr_equal(a, ips->addrs+i))
         return 1;
   }
   return 0;
}

/* vim:set ts=3 sw=3 tw=80 et: */
