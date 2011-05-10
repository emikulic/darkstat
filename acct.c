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
#include "decode.h"
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
#include <assert.h>
#include <ctype.h> /* for isdigit */
#include <netdb.h> /* for gai_strerror */
#include <stdlib.h> /* for free */
#include <string.h> /* for memcpy */

uint64_t total_packets = 0, total_bytes = 0;

static int using_localnet4 = 0, using_localnet6 = 0;
static struct addr localnet4, localmask4, localnet6, localmask6;

/* Parse the net/mask specification into two IPs or die trying. */
void
acct_init_localnet(const char *spec)
{
   char **tokens;
   int num_tokens, isnum, j, ret;
   int pfxlen, octets, remainder;
   struct addr localnet, localmask;

   tokens = split('/', spec, &num_tokens);
   if (num_tokens != 2)
      errx(1, "expecting network/netmask, got \"%s\"", spec);

   if ((ret = str_to_addr(tokens[0], &localnet)) != 0)
      errx(1, "couldn't parse \"%s\": %s", tokens[0], gai_strerror(ret));

   /* Detect a purely numeric argument.  */
   isnum = 0;
   {
      const char *p = tokens[1];
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
   }

   if (!isnum) {
      if ((ret = str_to_addr(tokens[1], &localmask)) != 0)
         errx(1, "couldn't parse \"%s\": %s", tokens[1], gai_strerror(ret));
      if (localmask.family != localnet.family)
         errx(1, "family mismatch between net and mask");
   } else {
      uint8_t frac, *p;

      localmask.family = localnet.family;

      /* Compute the prefix length.  */
      pfxlen = strtonum(tokens[1], 1,
                        (localnet.family == IPv6) ? 128 : 32, NULL);
      if (pfxlen == 0)
         errx(1, "invalid network prefix length \"%s\"", tokens[1]);

      /* Construct the network mask.  */
      octets = pfxlen / 8;
      remainder = pfxlen % 8;
      p = (localnet.family == IPv6) ? (localmask.ip.v6.s6_addr)
                                    : ((uint8_t *) &(localmask.ip.v4));

      if (localnet.family == IPv6)
         memset(p, 0, 16);
      else
         memset(p, 0, 4);

      for (j = 0; j < octets; ++j)
         p[j] = 0xff;

      frac = 0xff << (8 - remainder);
      if (frac)
         p[j] = frac;   /* Have contribution for next position.  */
   }

   free(tokens[0]);
   free(tokens[1]);
   free(tokens);

   /* Register the correct netmask and calculate the correct net.  */
   addr_mask(&localnet, &localmask);
   if (localnet.family == IPv6) {
      using_localnet6 = 1;
      localnet6 = localnet;
      localmask6 = localmask;
   } else {
      using_localnet4 = 1;
      localnet4 = localnet;
      localmask4 = localmask;
   }

   verbosef("local network address: %s", addr_to_str(&localnet));
   verbosef("   local network mask: %s", addr_to_str(&localmask));
}

static int
addr_is_local(const struct addr * const a)
{
   if (a->family == IPv4) {
      if (using_localnet4) {
         if (addr_inside(a, &localnet4, &localmask4))
            return 1;
      } else {
         if (addr_equal(a, &localip4))
            return 1;
      }
   } else {
      assert(a->family == IPv6);
      if (using_localnet6) {
         if (addr_inside(a, &localnet6, &localmask6))
            return 1;
      } else {
         if (addr_equal(a, &localip6))
            return 1;
      }
   }
   return 0;
}

/* Account for the given packet summary. */
void
acct_for(const struct pktsummary * const sm)
{
   struct bucket *hs = NULL, *hd = NULL;
   struct bucket *ps, *pd;
   int dir_in, dir_out;

#if 0 /* WANT_CHATTY? */
   printf("%15s > ", addr_to_str(&sm->src));
   printf("%15s ", addr_to_str(&sm->dst));
   printf("len %4d proto %2d", sm->len, sm->proto);

   if (sm->proto == IPPROTO_TCP || sm->proto == IPPROTO_UDP)
      printf(" port %5d : %5d", sm->src_port, sm->dst_port);
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
   dir_out = addr_is_local(&(sm->src));
   dir_in  = addr_is_local(&(sm->dst));

   /* Traffic staying within the network isn't counted. */
   if (dir_in == 1 && dir_out == 1)
      dir_in = dir_out = 0;

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
   hs = host_get(&(sm->src));
   hs->out   += sm->len;
   hs->total += sm->len;
   memcpy(hs->u.host.mac_addr, sm->src_mac, sizeof(sm->src_mac));
   hs->u.host.last_seen = now;

   hd = host_get(&(sm->dst)); /* this can invalidate hs! */
   hd->in    += sm->len;
   hd->total += sm->len;
   memcpy(hd->u.host.mac_addr, sm->dst_mac, sizeof(sm->dst_mac));
   hd->u.host.last_seen = now;

   /* Protocols. */
   hs = host_find(&(sm->src));
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

      if (sm->dst_port <= highest_port)
      {
         pd = host_get_port_tcp(hd, sm->dst_port);
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

      if (sm->dst_port <= highest_port)
      {
         pd = host_get_port_udp(hd, sm->dst_port);
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
