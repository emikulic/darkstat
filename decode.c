/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
 *
 * decode.c: packet decoding.
 *
 * Given a captured packet, decode it and fill out a pktsummary struct which
 * will be sent to the accounting code in acct.c
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "cdefs.h"
#include "decode.h"
#include "err.h"
#include "opt.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <assert.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> /* inet_ntoa() */
#include <net/if.h> /* struct ifreq */

/* need struct ether_header */
#ifdef __NetBSD__ /* works for NetBSD 5.1.2 */
# include <netinet/if_ether.h>
#else
# ifdef __OpenBSD__
#  include <sys/queue.h>
#  include <net/if_arp.h>
#  include <netinet/if_ether.h>
# else
#  ifdef __sun
#   include <sys/ethernet.h>
#   define ETHER_HDR_LEN 14
#  else
#   ifdef _AIX
#    include <netinet/if_ether.h>
#    define ETHER_HDR_LEN 14
#   else
#    include <net/ethernet.h>
#   endif
#  endif
# endif
#endif

#ifndef ETHERTYPE_PPPOE
# define ETHERTYPE_PPPOE 0x8864
#endif
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

#include <netinet/in_systm.h> /* n_long */
#include <netinet/ip.h> /* struct ip */
#include <netinet/ip6.h> /* struct ip6_hdr */
#define __FAVOR_BSD
#include <netinet/tcp.h> /* struct tcphdr */
#include <netinet/udp.h> /* struct udphdr */

#define PPP_HDR_LEN     4
#define FDDI_HDR_LEN    21
#define IP_HDR_LEN      sizeof(struct ip)
#define IPV6_HDR_LEN    sizeof(struct ip6_hdr)
#define TCP_HDR_LEN     sizeof(struct tcphdr)
#define UDP_HDR_LEN     sizeof(struct udphdr)
#define NULL_HDR_LEN    4
#define SLL_HDR_LEN     16
#define RAW_HDR_LEN     0

#ifndef IPV6_VERSION
# define IPV6_VERSION 0x60
#endif

#ifndef IPV6_VERSION_MASK
# define IPV6_VERSION_MASK 0xF0
#endif

static int decode_ether(DECODER_ARGS);
static int decode_loop(DECODER_ARGS);
static int decode_null(DECODER_ARGS);
static int decode_ppp(DECODER_ARGS);
static int decode_pppoe(DECODER_ARGS);
#ifdef DLT_LINUX_SLL
static int decode_linux_sll(DECODER_ARGS);
#endif
static int decode_raw(DECODER_ARGS);

#define HELPER_ARGS const u_char *pdata, \
                    const uint32_t len, \
                    struct pktsummary *sm

static int helper_pppoe(HELPER_ARGS);
static int helper_ip(HELPER_ARGS);
static int helper_ipv6(HELPER_ARGS);
static void helper_ip_deeper(HELPER_ARGS); /* protocols like TCP/UDP */
static int helper_tls(HELPER_ARGS); /* TLS */
static void helper_http(HELPER_ARGS); /* HTTP */

/* Link-type header information */
static const struct linkhdr linkhdrs[] = {
  /* linktype       hdrlen         handler       */
   { DLT_EN10MB,    ETHER_HDR_LEN, decode_ether },
   { DLT_LOOP,      NULL_HDR_LEN,  decode_loop },
   { DLT_NULL,      NULL_HDR_LEN,  decode_null },
   { DLT_PPP,       PPP_HDR_LEN,   decode_ppp },
#if defined(__NetBSD__)
   { DLT_PPP_SERIAL, PPP_HDR_LEN,  decode_ppp },
#endif
   { DLT_PPP_ETHER, PPPOE_HDR_LEN, decode_pppoe },
#ifdef DLT_LINUX_SLL
   { DLT_LINUX_SLL, SLL_HDR_LEN,   decode_linux_sll },
#endif
   { DLT_RAW,       RAW_HDR_LEN,   decode_raw },
};

/* Returns a pointer to the linkhdr record matching the given linktype, or
 * NULL if no matching entry found.
 */
const struct linkhdr *getlinkhdr(const int linktype) {
   const int n = sizeof(linkhdrs) / sizeof(*linkhdrs);
   size_t i;

   for (i=0; i < n; i++) {
      if (linkhdrs[i].linktype == linktype) return &(linkhdrs[i]);
   }
   return NULL;
}

/* Returns the minimum snaplen needed to decode everything up to and including
 * the TCP/UDP packet headers.
 */
int getsnaplen(const struct linkhdr *lh) {
   return (int)(lh->hdrlen + IPV6_HDR_LEN + MAX(TCP_HDR_LEN, UDP_HDR_LEN));
}

static int decode_ether(DECODER_ARGS) {
   u_short type;
   const struct ether_header *hdr = (const struct ether_header *)pdata;

   if (pheader->caplen < ETHER_HDR_LEN) {
      verbosef("ether: packet too short (%u bytes)", pheader->caplen);
      return 0;
   }
#ifdef __sun
   memcpy(sm->src_mac, hdr->ether_shost.ether_addr_octet, sizeof(sm->src_mac));
   memcpy(sm->dst_mac, hdr->ether_dhost.ether_addr_octet, sizeof(sm->dst_mac));
#else
   memcpy(sm->src_mac, hdr->ether_shost, sizeof(sm->src_mac));
   memcpy(sm->dst_mac, hdr->ether_dhost, sizeof(sm->dst_mac));
#endif
   type = ntohs(hdr->ether_type);
   switch (type) {
      case ETHERTYPE_IP:
      case ETHERTYPE_IPV6:
         if (!opt_want_pppoe)
            return helper_ip(pdata + ETHER_HDR_LEN,
                             pheader->caplen - ETHER_HDR_LEN,
                             sm);
         verbosef("ether: discarded IP packet, expecting PPPoE instead");
         return 0;
      case ETHERTYPE_PPPOE:
         if (opt_want_pppoe)
            return helper_pppoe(pdata + ETHER_HDR_LEN,
                                pheader->caplen - ETHER_HDR_LEN,
                                sm);
         verbosef("ether: got PPPoE frame: maybe you want --pppoe");
         return 0;
      case ETHERTYPE_ARP:
         /* known protocol, don't complain about it. */
         return 0;
      default:
         verbosef("ether: unknown protocol (0x%04x)", type);
         return 0;
   }
}

/* Very similar to decode_null, except on OpenBSD we need to think
 * about family endianness.
 */
static int decode_loop(DECODER_ARGS) {
   uint32_t family;

   if (pheader->caplen < NULL_HDR_LEN) {
      verbosef("loop: packet too short (%u bytes)", pheader->caplen);
      return 0;
   }
   family = *(const uint32_t *)pdata;
#ifdef __OpenBSD__
   family = ntohl(family);
#endif
   if (family == AF_INET)
      return helper_ip(pdata + NULL_HDR_LEN,
                       pheader->caplen - NULL_HDR_LEN, sm);
   if (family == AF_INET6)
      return helper_ipv6(pdata + NULL_HDR_LEN,
                         pheader->caplen - NULL_HDR_LEN, sm);
   verbosef("loop: unknown family (0x%04x)", family);
   return 0;
}

static int decode_null(DECODER_ARGS) {
   uint32_t family;

   if (pheader->caplen < NULL_HDR_LEN) {
      verbosef("null: packet too short (%u bytes)", pheader->caplen);
      return 0;
   }
   family = *(const uint32_t *)pdata;
   if (family == AF_INET)
      return helper_ip(pdata + NULL_HDR_LEN,
                       pheader->caplen - NULL_HDR_LEN,
                       sm);
   if (family == AF_INET6)
      return helper_ipv6(pdata + NULL_HDR_LEN,
                         pheader->caplen - NULL_HDR_LEN,
                         sm);
   verbosef("null: unknown family (0x%04x)", family);
   return 0;
}

static int decode_ppp(DECODER_ARGS) {
   if (pheader->caplen < PPPOE_HDR_LEN) {
      verbosef("ppp: packet too short (%u bytes)", pheader->caplen);
      return 0;
   }
   if (pdata[2] == 0x00 && pdata[3] == 0x21)
      return helper_ip(pdata + PPP_HDR_LEN,
                       pheader->caplen - PPP_HDR_LEN,
                       sm);
   verbosef("ppp: non-IP PPP packet; ignoring.");
   return 0;
}

static int decode_pppoe(DECODER_ARGS) {
   return helper_pppoe(pdata, pheader->caplen, sm);
}

#ifdef DLT_LINUX_SLL
/* very similar to decode_ether ... */
static int decode_linux_sll(DECODER_ARGS) {
   const struct sll_header {
      uint16_t packet_type;
      uint16_t device_type;
      uint16_t addr_length;
#define SLL_MAX_ADDRLEN 8
      uint8_t addr[SLL_MAX_ADDRLEN];
      uint16_t ether_type;
   } *hdr = (const struct sll_header *)pdata;
   u_short type;

   if (pheader->caplen < SLL_HDR_LEN) {
      verbosef("linux_sll: packet too short (%u bytes)", pheader->caplen);
      return 0;
   }
   type = ntohs(hdr->ether_type);
   switch (type) {
   case ETHERTYPE_IP:
   case ETHERTYPE_IPV6:
      return helper_ip(pdata + SLL_HDR_LEN,
                       pheader->caplen - SLL_HDR_LEN,
                       sm);
   case ETHERTYPE_ARP:
      /* known protocol, don't complain about it. */
      return 0;
   default:
      verbosef("linux_sll: unknown protocol (0x%04x)", type);
      return 0;
   }
}
#endif /* DLT_LINUX_SLL */

static int decode_raw(DECODER_ARGS) {
   return helper_ip(pdata, pheader->caplen, sm);
}

static int helper_pppoe(HELPER_ARGS) {
   if (len < PPPOE_HDR_LEN) {
      verbosef("pppoe: packet too short (%u bytes)", len);
      return 0;
   }

   if (pdata[1] != 0x00) {
      verbosef("pppoe: code = 0x%02x, expecting 0; ignoring.", pdata[1]);
      return 0;
   }

   if ((pdata[6] == 0xc0) && (pdata[7] == 0x21)) return 0; /* LCP */
   if ((pdata[6] == 0xc0) && (pdata[7] == 0x25)) return 0; /* LQR */

   if ((pdata[6] == 0x00) && (pdata[7] == 0x21))
      return helper_ip(pdata + PPPOE_HDR_LEN, len - PPPOE_HDR_LEN, sm);

   verbosef("pppoe: ignoring non-IP PPPoE packet (0x%02x%02x)",
            pdata[6], pdata[7]);
   return 0;
}

static int helper_ip(HELPER_ARGS) {
   const struct ip *hdr = (const struct ip *)pdata;

   if (len < IP_HDR_LEN) {
      verbosef("ip: packet too short (%u bytes)", len);
      return 0;
   }
   if (hdr->ip_v == 6) {
      return helper_ipv6(pdata, len, sm);
   }
   if (hdr->ip_v != 4) {
      verbosef("ip: version %d (expecting 4 or 6)", hdr->ip_v);
      return 0;
   }

   sm->len = ntohs(hdr->ip_len);
   sm->proto = hdr->ip_p;

   sm->src.family = IPv4;
   sm->src.ip.v4 = hdr->ip_src.s_addr;

   sm->dst.family = IPv4;
   sm->dst.ip.v4 = hdr->ip_dst.s_addr;

   helper_ip_deeper(pdata + IP_HDR_LEN, len - IP_HDR_LEN, sm);
   return 1;
}

static int helper_ipv6(HELPER_ARGS) {
   const struct ip6_hdr *hdr = (const struct ip6_hdr *)pdata;

   if (len < IPV6_HDR_LEN) {
      verbosef("ipv6: packet too short (%u bytes)", len);
      return 0;
   }
   if ((hdr->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
      verbosef("ipv6: bad version (%02x, expecting %02x)",
               hdr->ip6_vfc & IPV6_VERSION_MASK, IPV6_VERSION);
      return 0;
   }

   /* IPv4 has "total length," but IPv6 has "payload length" which doesn't
    * count the header bytes.
    */
   sm->len = ntohs(hdr->ip6_plen) + IPV6_HDR_LEN;
   sm->proto = hdr->ip6_nxt;
   sm->src.family = IPv6;
   memcpy(&sm->src.ip.v6, &hdr->ip6_src, sizeof(sm->src.ip.v6));
   sm->dst.family = IPv6;
   memcpy(&sm->dst.ip.v6, &hdr->ip6_dst, sizeof(sm->dst.ip.v6));

   helper_ip_deeper(pdata + IPV6_HDR_LEN, len - IPV6_HDR_LEN, sm);
   return 1;
}

static void helper_ip_deeper(HELPER_ARGS) {
   /* At this stage we have IP addresses so we can do host accounting.
    *
    * If proto decode fails, we set IPPROTO_INVALID to skip accounting of port
    * numbers.
    *
    * We don't need to "return 0" like other helpers.
    */
   switch (sm->proto) {
      case IPPROTO_TCP: {
         const struct tcphdr *thdr = (const struct tcphdr *)pdata;
         if (len < TCP_HDR_LEN) {
            verbosef("tcp: packet too short (%u bytes)", len);
            sm->proto = IPPROTO_INVALID; /* don't do accounting! */
            return;
         }
         sm->src_port = ntohs(thdr->th_sport);
         sm->dst_port = ntohs(thdr->th_dport);
         sm->tcp_flags = thdr->th_flags &
            (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG);

         const uint16_t header_len = (thdr->th_off)<<2;
         if (header_len < len) {
            if (helper_tls(pdata + header_len, len - header_len, sm))
               return;
            return helper_http(pdata + header_len, len - header_len, sm);
         }
      }

      case IPPROTO_UDP: {
         const struct udphdr *uhdr = (const struct udphdr *)pdata;
         if (len < UDP_HDR_LEN) {
            verbosef("udp: packet too short (%u bytes)", len);
            sm->proto = IPPROTO_INVALID; /* don't do accounting! */
            return;
         }
         sm->src_port = ntohs(uhdr->uh_sport);
         sm->dst_port = ntohs(uhdr->uh_dport);
         return;
      }
   }
}

static int helper_tls(HELPER_ARGS) {
   if (len < TLS_HDSHK_SESSION)
      return 0;
  
   if (pdata[TLS_HDR_TYPE] != TLS_CONTENT_TYPE_HANDSHAKE ||
       pdata[TLS_HDR_PROTO_MAJOR] != 3 ||
       pdata[TLS_HDSHK_TYPE] != TLS_HANDSHAKE_TYPE_HELLO )
       return 0;

   uint16_t   data_len, pos;

   pos = TLS_HDSHK_SESSION + pdata[TLS_HDSHK_SESSION_LENGTH];

   if (pos + 2 > len)
      return 0;
   pos += 2 + ntohs(*(uint16_t*)(pdata + pos)); /* Skip cipher suites */

   if (pos + 1 > len)
      return 0;
   pos += 1 + pdata[pos];  /* Skip compression methods */

   data_len = pos + 2 + ntohs(*(uint16_t*)(pdata + pos));
   pos += 2;

   if (data_len > len)
       data_len = len;

   while (pos < data_len - 4) {
      uint16_t extension_type, extension_length;
      extension_type = ntohs(*(uint16_t*)(pdata + pos));
      pos += 2;
      extension_length = ntohs(*(uint16_t*)(pdata + pos));
      pos += 2;
      
      if (extension_type != TLS_EXTENSION_HOST)
         pos += extension_length;
      else {
         if (pos + extension_length > data_len)
            return 0;

         uint16_t data_len = pos + 2 + ntohs(*(uint16_t*)(pdata + pos));
         pos += 2;
         
         if (data_len > len)
             data_len = len;
         
         while (pos < data_len - 3) {
            uint8_t  sni_type   = pdata[pos++];
            uint16_t sni_length = ntohs(*(uint16_t*)(pdata + pos));
            pos += 2;
            if (sni_type == TLS_SNI_TYPE_HOST) {
               sm->hostname = (const char*)(pdata + pos);
               sm->hostname_length = sni_length;
               return 1;
            }
            pos += sni_length;
         }
         return 0;
      }
   }

   return 0;
}

static void helper_http(HELPER_ARGS) {
   uint16_t pos, end;

   if (len < 4)
      return;

   if (memcmp(pdata, "GET", 3) && memcmp(pdata, "POST", 4))
      return;

   for (pos = 4; pos < len -1 ; pos++){
      if (pdata[pos] == '\r')
         return;
         
      /* Advance to next line */
      for (; pos < len && pdata[pos] != '\n'; pos++);
      if (pos >= len - 6)
         return;

      pos++;
      if ((pdata[pos]   == 'H' || pdata[pos]   == 'h') &&
          (pdata[pos+1] == 'O' || pdata[pos+1] == 'o') &&
          (pdata[pos+2] == 'S' || pdata[pos+2] == 's') &&
          (pdata[pos+3] == 'T' || pdata[pos+3] == 't') &&
           pdata[pos+4] == ':') {
         
         size_t   dots = 0, nondigits = 0;

         pos += 5;
         for (; pos < len && pdata[pos] <= ' '; pos++);
         for (end = pos; end < len && pdata[end] != '\r'; end++)
            if (pdata[end] == '.')
               dots++;
            else if ((pdata[end] < '0' || pdata[end] > '9') &&
                      pdata[end] != ':')
               nondigits++;

         if (nondigits == 0 && dots == 3)
            return;

         sm->hostname = (const char*)(pdata + pos);
         sm->hostname_length = end - pos;
         return;
      }
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
