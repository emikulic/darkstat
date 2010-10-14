/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
 *
 * acct.c: traffic accounting
 *
 * Permission to use, copy, modify, and distribute this file for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "darkstat.h"
#include "acct.h"
#include "conv.h"
#include "daylog.h"
#include "err.h"
#include "hosts_db.h"
#include "localip.h"
#include "now.h"

#include <arpa/inet.h> /* for inet_aton() */
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <stdlib.h> /* for free */
#include <string.h> /* for memcpy */
#include <ctype.h>  /* isdigit() */

uint64_t total_packets = 0, total_bytes = 0;

static int using_localnet = 0;
static int using_localnet6 = 0;
static in_addr_t localnet, localmask;
static struct in6_addr localnet6, localmask6;

/* Parse the net/mask specification into two IPs or die trying. */
void
acct_init_localnet(const char *spec)
{
   char **tokens, *p;
   int num_tokens, isnum, j;
   int build_ipv6;  /* Zero for IPv4, one for IPv6.  */
   int pfxlen, octets, remainder;
   struct in_addr addr;
   struct in6_addr addr6;

   tokens = split('/', spec, &num_tokens);
   if (num_tokens != 2)
      errx(1, "expecting network/netmask, got \"%s\"", spec);

   /* Presence of a colon distinguishes address families.  */
   if (strchr(tokens[0], ':')) {
      build_ipv6 = 1;
      if (inet_pton(AF_INET6, tokens[0], &addr6) != 1)
         errx(1, "invalid IPv6 network address \"%s\"", tokens[0]);
      memcpy(&localnet6, &addr6, sizeof(localnet6));
   } else {
      build_ipv6 = 0;
      if (inet_pton(AF_INET, tokens[0], &addr) != 1)
         errx(1, "invalid network address \"%s\"", tokens[0]);
      localnet = addr.s_addr;
   }

   /* Detect a purely numeric argument.  */
   isnum = 0;
   p = tokens[1];
   while (*p != '\0') {
      if (isdigit(*p)) {
         isnum = 1;
         ++p;
         continue;
      } else {
         isnum = 0;
         break;
      }
   }

   if (!isnum) {
      if (build_ipv6) {
         if (inet_pton(AF_INET6, tokens[1], &addr6) != 1)
            errx(1, "invalid IPv6 network mask \"%s\"", tokens[1]);
         memcpy(&localmask6, &addr6, sizeof(localmask6));
      } else {
         if (inet_pton(AF_INET, tokens[1], &addr) != 1)
            errx(1, "invalid network mask \"%s\"", tokens[1]);
         localmask = addr.s_addr;
      }
   } else {
      uint8_t frac, *p;

      /* Compute the prefix length.  */
      pfxlen = strtonum(tokens[1], 1, build_ipv6 ? 128 : 32, NULL);
      if (pfxlen == 0)
         errx(1, "invalid network prefix length \"%s\"", tokens[1]);

      /* Construct the network mask.  */
      octets = pfxlen / 8;
      remainder = pfxlen % 8;
      p = build_ipv6 ? (uint8_t *) localmask6.s6_addr : (uint8_t *) &localmask;

      if (build_ipv6)
         memset(&localmask6, 0, sizeof(localmask6));
      else
         memset(&localmask, 0, sizeof(localmask));

      for (j = 0; j < octets; ++j)
         p[j] = 0xff;

      frac = 0xff << (8 - remainder);
      if (frac)
         p[j] = frac;   /* Have contribution for next position.  */
   }

   /* Register the correct netmask and calculate the correct net.  */
   if (build_ipv6) {
      using_localnet6 = 1;
      for (j = 0; j < 16; ++j)
         localnet6.s6_addr[j] &= localmask6.s6_addr[j];
   } else {
      using_localnet = 1;
      localnet &= localmask;
   }

   free(tokens[0]);
   free(tokens[1]);
   free(tokens);

   if (build_ipv6) {
      verbosef("local network address: %s", ip_to_str_af(&localnet6, AF_INET6));
      verbosef("   local network mask: %s", ip_to_str_af(&localmask6, AF_INET6));
   } else {
      verbosef("local network address: %s", ip_to_str_af(&localnet, AF_INET));
      verbosef("   local network mask: %s", ip_to_str_af(&localmask, AF_INET));
   }

}

/* Account for the given packet summary. */
void
acct_for(const pktsummary *sm)
{
   struct bucket *hs = NULL, *hd = NULL;
   struct bucket *ps, *pd;
   struct addr46 ipaddr;
   struct in6_addr scribble;
   int dir_in, dir_out, j;

#if 0 /* WANT_CHATTY? */
   printf("%15s > ", ip_to_str_af(&sm->src_ip, AF_INET));
   printf("%15s ", ip_to_str_af(&sm->dest_ip, AF_INET));
   printf("len %4d proto %2d", sm->len, sm->proto);

   if (sm->proto == IPPROTO_TCP || sm->proto == IPPROTO_UDP)
      printf(" port %5d : %5d", sm->src_port, sm->dest_port);
   if (sm->proto == IPPROTO_TCP)
      printf(" %s%s%s%s%s%s",
         (sm->tcp_flags & TH_FIN)?"F":"",
         (sm->tcp_flags & TH_SYN)?"S":"",
         (sm->tcp_flags & TH_RST)?"R":"",
         (sm->tcp_flags & TH_PUSH)?"P":"",
         (sm->tcp_flags & TH_ACK)?"A":"",
         (sm->tcp_flags & TH_URG)?"U":""
      );
   printf("\n");
#endif

   /* Totals. */
   total_packets++;
   total_bytes += sm->len;

   /* Graphs. */
   dir_in = dir_out = 0;

   if (sm->af == AF_INET) {
      if (using_localnet) {
         if ((sm->src_ip.s_addr & localmask) == localnet)
            dir_out = 1;
         if ((sm->dest_ip.s_addr & localmask) == localnet)
            dir_in = 1;
         if (dir_in == 1 && dir_out == 1)
            /* Traffic staying within the network isn't counted. */
            dir_in = dir_out = 0;
      } else {
         if (memcmp(&sm->src_ip, &localip, sizeof(localip)) == 0)
            dir_out = 1;
         if (memcmp(&sm->dest_ip, &localip, sizeof(localip)) == 0)
            dir_in = 1;
      }
   } else if (sm->af == AF_INET6) {
      if (using_localnet6) {
         for (j = 0; j < 16; ++j)
            scribble.s6_addr[j] = sm->src_ip6.s6_addr[j] & localmask6.s6_addr[j];
         if (memcmp(&scribble, &localnet6, sizeof(scribble)) == 0)
            dir_out = 1;
         else {
            for (j = 0; j < 16; ++j)
               scribble.s6_addr[j] = sm->dest_ip6.s6_addr[j] & localmask6.s6_addr[j];
            if (memcmp(&scribble, &localnet6, sizeof(scribble)) == 0)
               dir_in = 1;
         }
      } else {
         if (memcmp(&sm->src_ip6, &localip6, sizeof(localip6)) == 0)
            dir_out = 1;
         if (memcmp(&sm->dest_ip6, &localip6, sizeof(localip6)) == 0)
            dir_in = 1;
      }
   }

   if (dir_out) {
      daylog_acct((uint64_t)sm->len, GRAPH_OUT);
      graph_acct((uint64_t)sm->len, GRAPH_OUT);
   }
   if (dir_in) {
      daylog_acct((uint64_t)sm->len, GRAPH_IN);
      graph_acct((uint64_t)sm->len, GRAPH_IN);
   }

   if (hosts_max == 0) return; /* skip per-host accounting */

   /* Hosts. */
   ipaddr.af = sm->af;
   switch (ipaddr.af) {
      case AF_INET6:
         memcpy(&ipaddr.addr.ip6, &sm->src_ip6, sizeof(ipaddr.addr.ip6));
         break;
      case AF_INET:
      default:
         memcpy(&ipaddr.addr.ip, &sm->src_ip, sizeof(ipaddr.addr.ip));
         break;
   }
   hs = host_get(&ipaddr);
   hs->out   += sm->len;
   hs->total += sm->len;
   memcpy(hs->u.host.mac_addr, sm->src_mac, sizeof(sm->src_mac));
   hs->u.host.last_seen = now;

   switch (ipaddr.af) {
      case AF_INET6:
         memcpy(&ipaddr.addr.ip6, &sm->dest_ip6, sizeof(ipaddr.addr.ip6));
         break;
      case AF_INET:
      default:
         memcpy(&ipaddr.addr.ip, &sm->dest_ip, sizeof(ipaddr.addr.ip));
         break;
   }
   hd = host_get(&ipaddr); /* this can invalidate hs! */
   hd->in    += sm->len;
   hd->total += sm->len;
   memcpy(hd->u.host.mac_addr, sm->dst_mac, sizeof(sm->dst_mac));
   hd->u.host.last_seen = now;

   /* Protocols. */
   switch (ipaddr.af) {
      case AF_INET6:
         memcpy(&ipaddr.addr.ip6, &sm->src_ip6, sizeof(ipaddr.addr.ip6));
         break;
      case AF_INET:
      default:
         memcpy(&ipaddr.addr.ip, &sm->src_ip, sizeof(ipaddr.addr.ip));
         break;
   }
   hs = host_find(&ipaddr);
   if (hs != NULL) {
      ps = host_get_ip_proto(hs, sm->proto);
      ps->out   += sm->len;
      ps->total += sm->len;
   }

   pd = host_get_ip_proto(hd, sm->proto);
   pd->in    += sm->len;
   pd->total += sm->len;

   if (ports_max == 0) return; /* skip ports accounting */

   /* Ports. */
   switch (sm->proto)
   {
   case IPPROTO_TCP:
      if ((sm->src_port <= highest_port) && (hs != NULL))
      {
         ps = host_get_port_tcp(hs, sm->src_port);
         ps->out   += sm->len;
         ps->total += sm->len;
      }

      if (sm->dest_port <= highest_port)
      {
         pd = host_get_port_tcp(hd, sm->dest_port);
         pd->in    += sm->len;
         pd->total += sm->len;
         if (sm->tcp_flags == TH_SYN)
            pd->u.port_tcp.syn++;
      }
      break;

   case IPPROTO_UDP:
      if ((sm->src_port <= highest_port) && (hs != NULL))
      {
         ps = host_get_port_udp(hs, sm->src_port);
         ps->out   += sm->len;
         ps->total += sm->len;
      }

      if (sm->dest_port <= highest_port)
      {
         pd = host_get_port_udp(hd, sm->dest_port);
         pd->in    += sm->len;
         pd->total += sm->len;
      }
      break;

   case IPPROTO_ICMP:
   case IPPROTO_ICMPV6:
   case IPPROTO_AH:
   case IPPROTO_ESP:
   case IPPROTO_OSPF:
      /* known protocol, don't complain about it */
      break;

   default:
      verbosef("unknown IP proto (%04x)", sm->proto);
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
