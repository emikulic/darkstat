/* darkstat 3
 * copyright (c) 2001-2009 Emil Mikulic.
 *
 * decode.h: packet decoding.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include <pcap.h>
#include <netinet/in.h> /* in_addr_t */

#define PPP_HDR_LEN     4
#define FDDI_HDR_LEN    21
#define IP_HDR_LEN      20
#define TCP_HDR_LEN     20
#define UDP_HDR_LEN     8
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

typedef struct {
   /* Fields are in host byte order (except IPs) */
   in_addr_t src_ip, dest_ip;
   time_t time;
   uint16_t len;
   uint8_t proto;                /* IPPROTO_{TCP, UDP, ICMP} */
   uint8_t tcp_flags;            /* only for TCP */
   uint16_t src_port, dest_port; /* only for TCP, UDP */
   uint8_t src_mac[ETHER_ADDR_LEN],
           dst_mac[ETHER_ADDR_LEN]; /* only for Ethernet */
} pktsummary;

/* vim:set ts=3 sw=3 tw=78 expandtab: */
