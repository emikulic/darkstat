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
#include <stdlib.h> /* for free */
#include <string.h> /* for memcpy */

uint64_t total_packets = 0, total_bytes = 0;

static int using_localnet = 0;
static in_addr_t localnet, localmask;

/* Parse the net/mask specification into two IPs or die trying. */
void
acct_init_localnet(const char *spec)
{
   char **tokens;
   int num_tokens;
   struct in_addr addr;

   tokens = split('/', spec, &num_tokens);
   if (num_tokens != 2)
      errx(1, "expecting network/netmask, got \"%s\"", spec);

   if (inet_aton(tokens[0], &addr) != 1)
      errx(1, "invalid network address \"%s\"", tokens[0]);
   localnet = addr.s_addr;

   if (inet_aton(tokens[1], &addr) != 1)
      errx(1, "invalid network mask \"%s\"", tokens[1]);
   localmask = addr.s_addr;
   /* FIXME: improve so we can accept masks like /24 for 255.255.255.0 */

   using_localnet = 1;
   free(tokens[0]);
   free(tokens[1]);
   free(tokens);

   verbosef("local network address: %s", ip_to_str(localnet));
   verbosef("   local network mask: %s", ip_to_str(localmask));

   if ((localnet & localmask) != localnet)
      errx(1, "this is an invalid combination of address and mask!\n"
      "it cannot match any address!");
}

/* Account for the given packet summary. */
void
acct_for(const pktsummary *sm)
{
   struct bucket *hs = NULL, *hd = NULL;
   struct bucket *ps, *pd;
   int dir_in, dir_out;

#if 0 /* WANT_CHATTY? */
   printf("%15s > ", ip_to_str(sm->src_ip));
   printf("%15s ", ip_to_str(sm->dest_ip));
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

   if (using_localnet) {
      if ((sm->src_ip & localmask) == localnet)
         dir_out = 1;
      if ((sm->dest_ip & localmask) == localnet)
         dir_in = 1;
      if (dir_in == 1 && dir_out == 1)
         /* Traffic staying within the network isn't counted. */
         dir_in = dir_out = 0;
   } else {
      if (sm->src_ip == localip)
         dir_out = 1;
      if (sm->dest_ip == localip)
         dir_in = 1;
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
   hs = host_get(sm->src_ip);
   hs->out   += sm->len;
   hs->total += sm->len;
   memcpy(hs->u.host.mac_addr, sm->src_mac, sizeof(sm->src_mac));
   hs->u.host.last_seen = now;

   hd = host_get(sm->dest_ip); /* this can invalidate hs! */
   hd->in    += sm->len;
   hd->total += sm->len;
   memcpy(hd->u.host.mac_addr, sm->dst_mac, sizeof(sm->dst_mac));
   hd->u.host.last_seen = now;

   /* Protocols. */
   hs = host_find(sm->src_ip);
   if (hs != NULL) {
      ps = host_get_ip_proto(hs, sm->proto);
      ps->out   += sm->len;
      ps->total += sm->len;
   }

   pd = host_get_ip_proto(hd, sm->proto);
   pd->in    += sm->len;
   pd->total += sm->len;

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
      /* known protocol, don't complain about it */
      break;

   default:
      verbosef("unknown IP proto (%04x)", sm->proto);
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
