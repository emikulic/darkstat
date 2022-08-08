/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
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

#include "acct.h"
#include "decode.h"
#include "conv.h"
#include "daylog.h"
#include "err.h"
#include "hosts_db.h"
#include "localip.h"
#include "now.h"
#include "opt.h"

#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <assert.h>
#include <ctype.h> /* for isdigit */
#include <netdb.h> /* for gai_strerror */
#include <stdlib.h> /* for free */
#include <string.h> /* for memcpy */

uint64_t acct_total_packets = 0, acct_total_bytes = 0;

static int using_localnet4 = 0, using_localnet6 = 0;
static struct addr localnet4, localmask4, localnet6, localmask6;

/* Parse the net/mask specification into two IPs or die trying. */
void
acct_init_localnet(const char *spec)
{
   char **tokens;
   unsigned int num_tokens;
   int isnum, j, ret;
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
      char *endptr;

      localmask.family = localnet.family;

      /* Compute the prefix length.  */
      pfxlen = (unsigned int)strtol(tokens[1], &endptr, 10);

      if ((pfxlen < 0) ||
          ((localnet.family == IPv6) && (pfxlen > 128)) ||
          ((localnet.family == IPv4) && (pfxlen > 32)) ||
          (tokens[1][0] == '\0') ||
          (*endptr != '\0'))
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

      frac = (uint8_t)(0xff << (8 - remainder));
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

static int addr_is_local(const struct addr * const a,
                         const struct local_ips *local_ips) {
   if (is_localip(a, local_ips))
      return 1;
   if (a->family == IPv4 && using_localnet4) {
      if (addr_inside(a, &localnet4, &localmask4))
         return 1;
   } else if (a->family == IPv6 && using_localnet6) {
      if (addr_inside(a, &localnet6, &localmask6))
         return 1;
   }
   return 0;
}

/* Account the peers.
 * Multiple connections to the same port are summarized */
void acct_peer(struct bucket *h, const struct addr *peer_addr,
               const uint16_t len, int dir_in,
               enum peer_port_tables o_ports,
               enum peer_port_tables o_ports_peer,
               uint16_t peer_port, uint16_t port)
{
   struct bucket *b_port, *b_port_peer;
   struct bucket *b = host_get_peer(h, peer_addr);
   struct peer *p = &(b->u.peer);

   /* Account peer */ 
   if (dir_in)
      b->in += len;
   else   
      b->out += len;
   b->total += len;

   /* Upon first occurence an entry for both tables local and peer
    * is created where peer is marked as hidden as we still do not
    * know on which port to summarize */

   /* Search for the port on the peer */
   b_port_peer = peer_find_port(p->ports[o_ports_peer], port);
   if (b_port_peer) {
      if (dir_in)
         b_port_peer->in += len;
      else
         b_port_peer->out += len;
      b_port_peer->total += len;
      if (!b_port_peer->u.peer_port.hidden)
         return;

      b_port = peer_find_port(p->ports[o_ports],
                              b_port_peer->u.peer_port.port_peer);

      if (b_port_peer->u.peer_port.port_peer == peer_port) {
         /* Still same port pair, just update as well */
         if (dir_in)
            b_port->in += len;
         else
            b_port->out += len;
         b_port->total += len;
         return;
      }

      /* Summarize on this entry and hide the other one */
      b_port_peer->u.peer_port.hidden = 0;
      b_port_peer->u.peer_port.port_peer = 0;
      b_port->u.peer_port.hidden = 1;
      return;
    }

   /* Search or create the port on this host */
   b_port = peer_get_port(p->ports + o_ports, peer_port);
   if (b_port->total) {
      /* If there is not the first entry and the port is different
       * then remove the port number and show 'multiple' */ 
      if (b_port->u.peer_port.port_peer != port)
         b_port->u.peer_port.port_peer = 0;
   } else {
      /* New entry*/
      b_port->u.peer_port.port_peer = port;
      /* Add in both directions for lookup, but mark as hidden */
      b_port_peer = peer_get_port(p->ports + o_ports_peer, port);
      b_port_peer->u.peer_port.hidden = 1;
      b_port_peer->u.peer_port.port_peer = peer_port;
      if (dir_in)
         b_port_peer->out += len;
      else
         b_port_peer->in += len;
      b_port_peer->total += len;
   }

   if (dir_in)
      b_port->in += len;
   else
      b_port->out += len;
   b_port->total += len;
}

/* Account for the given packet summary. */
void acct_for(const struct pktsummary * const sm,
              const struct local_ips * const local_ips) {
   struct bucket *hs = NULL;  // Source host.
   struct bucket *hd = NULL;  // Dest host.
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
   acct_total_packets++;
   acct_total_bytes += sm->len;

   /* Graphs. */
   dir_out = addr_is_local(&sm->src, local_ips);
   dir_in  = addr_is_local(&sm->dst, local_ips);

   /* Traffic staying within the network isn't counted. */
   if (dir_out && !dir_in) {
      daylog_acct((uint64_t)sm->len, GRAPH_OUT);
      graph_acct((uint64_t)sm->len, GRAPH_OUT);
   }
   if (dir_in && !dir_out) {
      daylog_acct((uint64_t)sm->len, GRAPH_IN);
      graph_acct((uint64_t)sm->len, GRAPH_IN);
   }

   if (opt_hosts_max == 0) return; /* skip per-host accounting */

   /* Hosts. */
   hosts_db_reduce();
   if (!opt_want_local_only || dir_out) {
      hs = host_get(&(sm->src));
      hs->out   += sm->len;
      hs->total += sm->len;
      memcpy(hs->u.host.mac_addr, sm->src_mac, sizeof(sm->src_mac));
      hs->u.host.last_seen_mono = now_mono();
   }

   if (!opt_want_local_only || dir_in) {
      hd = host_get(&(sm->dst));
      hd->in    += sm->len;
      hd->total += sm->len;
      memcpy(hd->u.host.mac_addr, sm->dst_mac, sizeof(sm->dst_mac));
      /*
       * Don't update recipient's last seen time, we don't know that
       * they received successfully.
       */
   }

   /* Protocols. */
   if (sm->proto != IPPROTO_INVALID) {
      if (hs) {
         struct bucket *ps = host_get_ip_proto(hs, sm->proto);
         ps->out   += sm->len;
         ps->total += sm->len;
      }
      if (hd) {
         struct bucket *pd = host_get_ip_proto(hd, sm->proto);
         pd->in    += sm->len;
         pd->total += sm->len;
      }
   }

   if (opt_want_peers && sm->proto != IPPROTO_INVALID &&
       sm->proto != IPPROTO_TCP && sm->proto != IPPROTO_UDP) {
      if (hs) {
         struct bucket *p = host_get_peer(hs, &(sm->dst));
         struct bucket *ps = peer_get_ip_proto(p, sm->proto);
         ps->out   += sm->len;
         ps->total += sm->len;
      }
      if (hd) {
         struct bucket *p = host_get_peer(hd, &(sm->src));
         struct bucket *pd = peer_get_ip_proto(p, sm->proto);
         pd->in    += sm->len;
         pd->total += sm->len;
      }
   }

   if (opt_ports_max == 0) return; /* skip ports accounting */

   /* Ports. */
   switch (sm->proto) {
   case IPPROTO_TCP:
      // Local ports on host.
      if (opt_want_ports) {
         if ((sm->src_port <= opt_highest_port) && hs) {
            struct bucket *ps = host_get_port_tcp(hs, sm->src_port);
            ps->out   += sm->len;
            ps->total += sm->len;
         }
         if ((sm->dst_port <= opt_highest_port) && hd) {
            struct bucket *pd = host_get_port_tcp(hd, sm->dst_port);
            pd->in    += sm->len;
            pd->total += sm->len;
            if (sm->tcp_flags == TH_SYN)
               pd->u.port_tcp.syn++;
         }

         // Remote ports.
         if ((sm->src_port <= opt_highest_port) && hd) {
            struct bucket *pdr = host_get_port_tcp_remote(hd, sm->src_port);
            pdr->out   += sm->len;
            pdr->total += sm->len;
         }
         if ((sm->dst_port <= opt_highest_port) && hs) {
            struct bucket *psr = host_get_port_tcp_remote(hs, sm->dst_port);
            psr->in    += sm->len;
            psr->total += sm->len;
            if (sm->tcp_flags == TH_SYN)
               psr->u.port_tcp.syn++;
         }
      }
      
      if (opt_want_peers) {
         if ((sm->src_port <= opt_highest_port) && hd)
            acct_peer(hd, &(sm->src), sm->len, 1,
                      PEER_PORT_TCP, PEER_PORT_TCP_PEER,
                      sm->src_port, sm->dst_port);

         if ((sm->dst_port <= opt_highest_port) && hs)
            acct_peer(hs, &(sm->dst), sm->len, 0,
                      PEER_PORT_TCP, PEER_PORT_TCP_PEER,
                      sm->dst_port, sm->src_port);
      }
      break;

   case IPPROTO_UDP:
      // Local ports on host.
      if (opt_want_ports) {
         if ((sm->src_port <= opt_highest_port) && hs) {
            struct bucket *ps = host_get_port_udp(hs, sm->src_port);
            ps->out   += sm->len;
            ps->total += sm->len;
         }
         if ((sm->dst_port <= opt_highest_port) && hd) {
            struct bucket *pd = host_get_port_udp(hd, sm->dst_port);
            pd->in    += sm->len;
            pd->total += sm->len;
         }

         // Remote ports.
         if ((sm->src_port <= opt_highest_port) && hd) {
            struct bucket *pdr = host_get_port_udp_remote(hd, sm->src_port);
            pdr->out   += sm->len;
            pdr->total += sm->len;
         }
         if ((sm->dst_port <= opt_highest_port) && hs) {
            struct bucket *psr = host_get_port_udp_remote(hs, sm->dst_port);
            psr->in    += sm->len;
            psr->total += sm->len;
         }
      }

      if (opt_want_peers) {
         if (opt_want_peers && (sm->src_port <= opt_highest_port) && hd)
            acct_peer(hd, &(sm->src), sm->len, 1,
                      PEER_PORT_UDP, PEER_PORT_UDP_PEER,
                      sm->src_port, sm->dst_port);

         if (opt_want_peers && (sm->dst_port <= opt_highest_port) && hs)
            acct_peer(hs, &(sm->dst), sm->len, 0,
                      PEER_PORT_UDP, PEER_PORT_UDP_PEER,
                      sm->dst_port, sm->src_port);
      }
      break;

   case IPPROTO_INVALID:
      /* proto decoding failed, don't complain in accounting */
      break;
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
