/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * hosts_db.h: database of hosts, ports, protocols.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */
#ifndef __DARKSTAT_HOSTS_DB_H
#define __DARKSTAT_HOSTS_DB_H

#include <sys/types.h> /* for uint64_t */

#include "addr.h"

struct hashtable;

struct host {
   struct addr addr;
   char *dns;
   uint8_t mac_addr[6];
   /* last_seen_mono is converted to/from time_t in export/import.
    * It can be negative (due to machine reboots).
    */
   int64_t last_seen_mono;
   struct hashtable *ports_tcp;
   struct hashtable *ports_tcp_remote;
   struct hashtable *ports_udp;
   struct hashtable *ports_udp_remote;
   struct hashtable *ip_protos;
   struct hashtable *peers;
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

enum peer_port_tables {
   PEER_PORT_TCP = 0,
   PEER_PORT_TCP_PEER = 1,
   PEER_PORT_UDP = 2,
   PEER_PORT_UDP_PEER = 3,
   PEER_PORT_TABLES = 4
};

struct peer {
   struct addr addr;
   struct hashtable *ports[PEER_PORT_TABLES];
};

struct peer_port {
   uint16_t port;
   uint16_t port_peer;
   uint8_t  hidden;
};

struct bucket {
   struct bucket *next;
   uint64_t in, out, total;
   union {
      struct host host;
      struct port_tcp port_tcp;
      struct port_udp port_udp;
      struct ip_proto ip_proto;
      struct peer peer;
      struct peer_port peer_port;
   } u;
};

enum sort_dir { IN, OUT, TOTAL, LASTSEEN };

extern int hosts_db_show_macs;

void hosts_db_init(void);
void hosts_db_reduce(void);
void hosts_db_reset(void);
void hosts_db_free(void);
int hosts_db_import(const int fd);
int hosts_db_export(const int fd);

struct bucket *host_find(const struct addr *const a); /* can return NULL */
struct bucket *host_get(const struct addr *const a);
struct bucket *host_get_port_tcp(struct bucket *host, const uint16_t port);
struct bucket *host_get_port_tcp_remote(struct bucket *host,
                                        const uint16_t port);
struct bucket *host_get_port_udp(struct bucket *host, const uint16_t port);
struct bucket *host_get_port_udp_remote(struct bucket *host,
                                        const uint16_t port);
struct bucket *host_get_ip_proto(struct bucket *host, const uint8_t proto);
struct bucket *host_get_peer(struct bucket *host, const struct addr *const a);
struct bucket *peer_find_port(struct hashtable *table, uint16_t port);
struct bucket *peer_get_port(struct hashtable **table, uint16_t port);

/* Web pages. */
struct str *html_hosts(const char *uri, const char *query);
struct str *text_metrics();

/* From hosts_sort */
void qsort_buckets(const struct bucket **a, size_t n,
   size_t left, size_t right, const enum sort_dir d);

#endif /* __DARKSTAT_HOSTS_DB_H */
/* vim:set ts=3 sw=3 tw=78 expandtab: */
