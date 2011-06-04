/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * decode.h: packet decoding.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */
#ifndef __DARKSTAT_DECODE_H
#define __DARKSTAT_DECODE_H

#include <pcap.h>
#include <netinet/in_systm.h>	/* n_time */
#define __USE_GNU 1
#include <netinet/in.h> /* for <netinet/ip.h>  */
#include <netinet/ip.h> /* struct ip */

#include "addr.h"

#define PPP_HDR_LEN     4
#define FDDI_HDR_LEN    21
#define IP_HDR_LEN      sizeof(struct ip)
#define IPV6_HDR_LEN    sizeof(struct ip6_hdr)
#define TCP_HDR_LEN     sizeof(struct tcphdr)
#define UDP_HDR_LEN     sizeof(struct udphdr)
#define NULL_HDR_LEN    4
#define PPPOE_HDR_LEN   8
#define SLL_HDR_LEN     16
#define RAW_HDR_LEN     0

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#ifndef IPPROTO_OSPF
#  define IPPROTO_OSPF 89
#endif

#define IPPROTO_INVALID 254 /* don't do proto accounting */

struct linkhdr {
   int linktype;
   unsigned int hdrlen;
   pcap_handler handler;
};

const struct linkhdr *getlinkhdr(const int linktype);
int getsnaplen(const struct linkhdr *lh);

struct pktsummary {
   /* Fields are in host byte order (except IPs) */
   struct addr src, dst;
   time_t time;
   uint16_t len;
   uint8_t proto;               /* IPPROTO_{TCP, UDP, ICMP} */
   uint8_t tcp_flags;           /* only for TCP */
   uint16_t src_port, dst_port; /* only for TCP, UDP */
   uint8_t src_mac[ETHER_ADDR_LEN],
           dst_mac[ETHER_ADDR_LEN]; /* only for Ethernet */
};

#endif /* __DARKSTAT_DECODE_H */
/* vim:set ts=3 sw=3 tw=78 expandtab: */
