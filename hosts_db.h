/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
 *
 * hosts_db.h: database of hosts, ports, protocols.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include <sys/types.h>
#include <netinet/in.h>
#include "str.h"

struct hashtable;

struct host {
   union {
      in_addr_t ip;
      struct in6_addr ip6;
   };
   sa_family_t af;
   char *dns;
   uint8_t mac_addr[6];
   time_t last_seen;
   struct hashtable *ports_tcp, *ports_udp, *ip_protos;
};

struct port_tcp {
   uint16_t port;
   uint64_t syn;
};

struct port_udp {
   uint16_t port;
};

struct ip_proto {
   uint8_t proto;
};

struct bucket {
   struct bucket *next;
   uint64_t in, out, total;
   union {
      struct host host;
      struct port_tcp port_tcp;
      struct port_udp port_udp;
      struct ip_proto ip_proto;
   } u;
};

enum sort_dir { IN, OUT, TOTAL };

extern int show_mac_addrs;

/*
 * Table reduction - when the number of entries is about to exceed <max>, we
 * reduce the table to the top <keep> entries.
 */
extern unsigned int hosts_max, hosts_keep, ports_max, ports_keep;

void hosts_db_init(void);
void hosts_db_reduce(void);
void hosts_db_reset(void);
void hosts_db_free(void);
int hosts_db_import(const int fd);
int hosts_db_export(const int fd);

struct bucket *host_find(const in_addr_t ip); /* can return NULL */
struct bucket *host_get(const in_addr_t ip);
struct bucket *host_get_port_tcp(struct bucket *host, const uint16_t port);
struct bucket *host_get_port_udp(struct bucket *host, const uint16_t port);
struct bucket *host_get_ip_proto(struct bucket *host, const uint8_t proto);

/* Web pages. */
struct str *html_hosts(const char *uri, const char *query);

/* From hosts_sort */
void qsort_buckets(const struct bucket **a, size_t n,
   size_t left, size_t right, const enum sort_dir d);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
