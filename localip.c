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
#include "decode.h" /* for ip_to_str */
#include "err.h"
#include "localip.h"

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h> /* for SIOCGIFADDR, especially on Solaris */
#endif
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static const char *iface = NULL;
in_addr_t localip = 0;
static in_addr_t last_localip = 0;

void
localip_init(const char *interface)
{
   iface = interface;
   localip_update();
}

void
localip_update(void)
{
   int tmp = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
   struct ifreq ifr;
   struct sockaddr sa;

   if (iface == NULL) {
      /* reading from capfile */
      localip = 0;
      return;
   }

   strlcpy(ifr.ifr_name, iface, IFNAMSIZ);
   ifr.ifr_addr.sa_family = AF_INET;
   if (ioctl(tmp, SIOCGIFADDR, &ifr) == -1) {
      if (errno == EADDRNOTAVAIL) {
         /* lost IP, e.g. ifconfig eth0 delete, don't die */
         localip = 0;
         close(tmp);
         return;
      } else
         err(1, "can't get own IP address on interface \"%s\"", iface);
   }
   close(tmp);
   sa = ifr.ifr_addr;

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

   localip = ((struct sockaddr_in*)&sa)->sin_addr.s_addr;
   if (last_localip != localip) {
      verbosef("local_ip update(%s) = %s", iface, ip_to_str(localip));
      last_localip = localip;
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
