/* darkstat 3
 * copyright (c) 2001-2009 Emil Mikulic.
 *
 * decode.h: packet decoding.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include <pcap.h>
#include <netinet/in_systm.h>	/* n_time */
#include <netinet/in.h> /* in_addr_t */
#include <netinet/ip.h> /* struct ip */

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

typedef struct {
   int linktype;
   unsigned int hdrlen;
   pcap_handler handler;
} linkhdr_t;

const linkhdr_t *getlinkhdr(int linktype);
int getsnaplen(const linkhdr_t *lh);
char *ip_to_str(const in_addr_t ip);
char *ip6_to_str(const struct in6_addr *ip6);

typedef struct {
   /* Fields are in host byte order (except IPs) */
   union {
      in_addr_t src_ip;
      struct in6_addr src_ip6;
   };
   union {
      in_addr_t dest_ip;
      struct in6_addr dest_ip6;
   };
   time_t time;
   uint16_t len;
   uint8_t af;                   /* AF_{UNSPEC, INET, INET6} */
   uint8_t proto;                /* IPPROTO_{TCP, UDP, ICMP} */
   uint8_t tcp_flags;            /* only for TCP */
   uint16_t src_port, dest_port; /* only for TCP, UDP */
   uint8_t src_mac[ETHER_ADDR_LEN],
           dst_mac[ETHER_ADDR_LEN]; /* only for Ethernet */
} pktsummary;

/* vim:set ts=3 sw=3 tw=78 expandtab: */
