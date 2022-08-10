/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
 *
 * decode.h: packet decoding.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */
#ifndef __DARKSTAT_DECODE_H
#define __DARKSTAT_DECODE_H

#include "addr.h"

#ifndef ETHER_ADDR_LEN
# define ETHER_ADDR_LEN 6
#endif

#define IPPROTO_INVALID 254 /* special: means don't do proto accounting */

#ifndef IPPROTO_OSPF
# define IPPROTO_OSPF 89
#endif

#define PPPOE_HDR_LEN 8

/* Decoding creates a summary which is passed to accounting. */
struct pktsummary {
   /* Fields are in host byte order (except IPs) */
   struct addr src, dst;
   uint16_t len;
   uint8_t proto; /* IPPROTO_INVALID means don't do proto accounting */
   uint8_t tcp_flags;           /* only for TCP */
   uint16_t src_port, dst_port; /* only for TCP, UDP */
   uint8_t src_mac[ETHER_ADDR_LEN], /* only for Ethernet */
           dst_mac[ETHER_ADDR_LEN]; /* only for Ethernet */
   const char*    hostname;
   uint8_t        hostname_length;
};

struct pcap_pkthdr; /* from pcap.h */

#define DECODER_ARGS const struct pcap_pkthdr *pheader, \
                     const u_char *pdata, \
                     struct pktsummary *sm

/* Returns 0 on decode failure (meaning accounting should not be performed) */
typedef int (decoder_fn)(DECODER_ARGS);

struct linkhdr {
   int linktype;
   unsigned int hdrlen;
   decoder_fn *decoder;
};

const struct linkhdr *getlinkhdr(const int linktype);
int getsnaplen(const struct linkhdr *lh);

#define TLS_HDR_LEN 5
#define TLS_HDR_TYPE        0
#define TLS_HDR_PROTO_MAJOR 1
#define TLS_HDR_PROTO_MINOR 2
#define TLS_HDR_DATA_LENGTH 3

#define TLS_HDSHK_TYPE           5
#define TLS_HDSHK_LENGTH         6
#define TLS_HDSHK_PROTO_MAJOR    9
#define TLS_HDSHK_PROTO_MINOR    10
#define TLS_HDSHK_RANDOM         11
#define TLS_HDSHK_SESSION_LENGTH 43
#define TLS_HDSHK_SESSION        44

#define TLS_CONTENT_TYPE_HANDSHAKE  22
#define TLS_HANDSHAKE_TYPE_HELLO    1

#define TLS_EXTENSION_HOST          0
#define TLS_SNI_TYPE_HOST           0

#endif /* __DARKSTAT_DECODE_H */
/* vim:set ts=3 sw=3 tw=78 expandtab: */
