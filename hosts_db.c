/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * hosts_db.c: database of hosts, ports, protocols.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "cdefs.h"
#include "conv.h"
#include "decode.h"
#include "dns.h"
#include "err.h"
#include "hosts_db.h"
#include "db.h"
#include "html.h"
#include "ncache.h"
#include "now.h"
#include "opt.h"
#include "str.h"

#include <netdb.h>  /* struct addrinfo */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset(), strcmp() */
#include <time.h>
#include <unistd.h>

int hosts_db_show_macs = 0;

/* FIXME: specify somewhere more sane/tunable */
#define MAX_ENTRIES 30 /* in an HTML table rendered from a hashtable */

typedef uint32_t (hash_func_t)(const struct hashtable *, const void *);
typedef void (free_func_t)(struct bucket *);
typedef const void * (key_func_t)(const struct bucket *);
typedef int (find_func_t)(const struct bucket *, const void *);
typedef struct bucket * (make_func_t)(const void *);
typedef void (format_cols_func_t)(struct str *);
typedef void (format_row_func_t)(struct str *, const struct bucket *);

struct hashtable {
   uint8_t bits;     /* size of hashtable in bits */
   uint32_t size, mask;
   uint32_t count, count_max, count_keep;   /* items in table */
   uint32_t coeff;   /* coefficient for Fibonacci hashing */
   struct bucket **table;

   struct {
      uint64_t inserts, searches, deletions, rehashes;
   } stats;

   hash_func_t *hash_func;
   /* returns hash value of given key (passed as void*) */

   free_func_t *free_func;
   /* free of bucket payload */

   key_func_t *key_func;
   /* returns pointer to key of bucket (to pass to hash_func) */

   find_func_t *find_func;
   /* returns true if given bucket matches key (passed as void*) */

   make_func_t *make_func;
   /* returns bucket containing new record with key (passed as void*) */

   format_cols_func_t *format_cols_func;
   /* append table columns to str */

   format_row_func_t *format_row_func;
   /* format record and append to str */
};

static void hashtable_reduce(struct hashtable *ht);
static void hashtable_free(struct hashtable *h);

#define HOST_BITS 1  /* initial size of hosts table */
#define PORT_BITS 1  /* initial size of ports tables */
#define PROTO_BITS 1 /* initial size of proto table */

/* We only use one hosts_db hashtable and this is it. */
static struct hashtable *hosts_db = NULL;

/* phi^-1 (reciprocal of golden ratio) = (sqrt(5) - 1) / 2 */
static const double phi_1 =
   0.61803398874989490252573887119069695472717285156250;

/* Co-prime of u, using phi^-1 */
static uint32_t coprime(const uint32_t u) {
   return ( (uint32_t)( (double)(u) * phi_1 ) | 1U );
}

/*
 * This is the "recommended" IPv4 hash function, as seen in FreeBSD's
 * src/sys/netinet/tcp_hostcache.c 1.1
 */
static uint32_t ipv4_hash(const struct addr *const a) {
   uint32_t ip = a->ip.v4;
   return ( (ip) ^ ((ip) >> 7) ^ ((ip) >> 17) );
}

#ifndef s6_addr32
# ifdef sun
/*
 * http://src.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/uts/common/netinet/in.h#130
 */
#  define s6_addr32 _S6_un._S6_u32
# else
/* Covers OpenBSD and FreeBSD.  The macro __USE_GNU has
 * taken care of GNU/Linux and GNU/kfreebsd.  */
#  define s6_addr32 __u6_addr.__u6_addr32
# endif
#endif

/*
 * This is the IPv6 hash function used by FreeBSD in the same file as above,
 * svn rev 122922.
 */
static uint32_t ipv6_hash(const struct addr *const a) {
   const struct in6_addr *const ip6 = &(a->ip.v6);
   return ( ip6->s6_addr32[0] ^ ip6->s6_addr32[1] ^
            ip6->s6_addr32[2] ^ ip6->s6_addr32[3] );
}

/* ---------------------------------------------------------------------------
 * hash_func collection
 */
static uint32_t
hash_func_host(const struct hashtable *h _unused_, const void *key)
{
   const struct addr *a = key;
   if (a->family == IPv4)
      return (ipv4_hash(a));
   else {
      assert(a->family == IPv6);
      return (ipv6_hash(a));
   }
}

#define CASTKEY(type) (*((const type *)key))

static uint32_t
hash_func_short(const struct hashtable *h, const void *key)
{
   return (CASTKEY(uint16_t) * h->coeff);
}

static uint32_t
hash_func_byte(const struct hashtable *h, const void *key)
{
   return (CASTKEY(uint8_t) * h->coeff);
}

/* ---------------------------------------------------------------------------
 * key_func collection
 */

static const void *
key_func_host(const struct bucket *b)
{
   return &(b->u.host.addr);
}

static const void *
key_func_port_tcp(const struct bucket *b)
{
   return &(b->u.port_tcp.port);
}

static const void *
key_func_port_udp(const struct bucket *b)
{
   return &(b->u.port_udp.port);
}

static const void *
key_func_ip_proto(const struct bucket *b)
{
   return &(b->u.ip_proto.proto);
}

static const void *
key_func_peer_port(const struct bucket *b)
{
   return &(b->u.peer_port.port);
}

/* ---------------------------------------------------------------------------
 * find_func collection
 */

static int
find_func_host(const struct bucket *b, const void *key)
{
   return (addr_equal(key, &(b->u.host.addr)));
}

static int
find_func_port_tcp(const struct bucket *b, const void *key)
{
   return (b->u.port_tcp.port == CASTKEY(uint16_t));
}

static int
find_func_port_udp(const struct bucket *b, const void *key)
{
   return (b->u.port_udp.port == CASTKEY(uint16_t));
}

static int
find_func_ip_proto(const struct bucket *b, const void *key)
{
   return (b->u.ip_proto.proto == CASTKEY(uint8_t));
}

static int
find_func_peer_port(const struct bucket *b, const void *key)
{
   return (b->u.peer_port.port == CASTKEY(uint16_t));
}

/* ---------------------------------------------------------------------------
 * make_func collection
 */

#define MAKE_BUCKET(name_bucket, name_content, type) struct { \
   struct bucket *next; \
   uint64_t in, out, total; \
   union { struct type t; } u; } _custom_bucket; \
   struct bucket *name_bucket = xcalloc(1, sizeof(_custom_bucket)); \
   struct type *name_content = &(name_bucket->u.type); \
   name_bucket->next = NULL; \
   name_bucket->in = name_bucket->out = name_bucket->total = 0;

static struct bucket *
make_func_host(const void *key)
{
   MAKE_BUCKET(b, h, host);
   h->addr = CASTKEY(struct addr);
   h->dns = NULL;
   h->last_seen_mono = 0;
   memset(&h->mac_addr, 0, sizeof(h->mac_addr));
   h->ports_tcp = NULL;
   h->ports_tcp_remote = NULL;
   h->ports_udp = NULL;
   h->ports_udp_remote = NULL;
   h->ip_protos = NULL;
   h->peers = NULL;
   return (b);
}

static void
free_func_host(struct bucket *b)
{
   struct host *h = &(b->u.host);
   if (h->dns != NULL) free(h->dns);
   hashtable_free(h->ports_tcp);
   hashtable_free(h->ports_tcp_remote);
   hashtable_free(h->ports_udp);
   hashtable_free(h->ports_udp_remote);
   hashtable_free(h->ip_protos);
   hashtable_free(h->peers);
}

static struct bucket *
make_func_port_tcp(const void *key)
{
   MAKE_BUCKET(b, p, port_tcp);
   p->port = CASTKEY(uint16_t);
   p->syn = 0;
   return (b);
}

static struct bucket *
make_func_port_udp(const void *key)
{
   MAKE_BUCKET(b, p, port_udp);
   p->port = CASTKEY(uint16_t);
   return (b);
}

static struct bucket *
make_func_ip_proto(const void *key)
{
   MAKE_BUCKET(b, p, ip_proto);
   p->proto = CASTKEY(uint8_t);
   return (b);
}

static struct bucket *
make_func_peer(const void *key)
{
   MAKE_BUCKET(b, p, peer);
   p->addr = CASTKEY(struct addr);
   p->ports[PEER_PORT_TCP] = NULL;
   p->ports[PEER_PORT_TCP_PEER] = NULL;
   p->ports[PEER_PORT_UDP] = NULL;
   p->ports[PEER_PORT_UDP_PEER] = NULL;
   return (b);
}

static struct bucket *
make_func_peer_port(const void *key)
{
   MAKE_BUCKET(b, p, peer_port);
   p->port = CASTKEY(uint16_t);
   return (b);
}

static void
free_func_peer(struct bucket *b)
{
   struct peer *p = &(b->u.peer);
   hashtable_free(p->ports[PEER_PORT_TCP]);
   hashtable_free(p->ports[PEER_PORT_TCP_PEER]);
   hashtable_free(p->ports[PEER_PORT_UDP]);
   hashtable_free(p->ports[PEER_PORT_UDP_PEER]);
}

static void
free_func_simple(struct bucket *b _unused_)
{
   /* nop */
}

/* ---------------------------------------------------------------------------
 * format_func collection (ordered by struct)
 */

static void
format_cols_host(struct str *buf)
{
   /* FIXME: don't clobber parts of the query string
    * specifically "full" and "start"
    * when setting sort direction
    */
   str_append(buf,
      "<table>\n"
      "<tr>\n"
      " <th>IP</th>\n"
      " <th>Hostname</th>\n");
   if (hosts_db_show_macs) str_append(buf,
      " <th>MAC Address</th>\n");
   str_append(buf,
      " <th><a href=\"?sort=in\">In</a></th>\n"
      " <th><a href=\"?sort=out\">Out</a></th>\n"
      " <th><a href=\"?sort=total\">Total</a></th>\n");
   if (opt_want_lastseen) str_append(buf,
      " <th><a href=\"?sort=lastseen\">Last seen</a></th>\n");
   str_append(buf,
      "</tr>\n");
}

static void
format_row_host(struct str *buf, const struct bucket *b)
{
   const char *ip = addr_to_str(&(b->u.host.addr));

   str_appendf(buf,
      "<tr>\n"
      " <td><a href=\"./%s/\">%s</a></td>\n"
      " <td>%s</td>\n",
      ip, ip,
      (b->u.host.dns == NULL) ? "" : b->u.host.dns);

   if (hosts_db_show_macs)
      str_appendf(buf,
         " <td><tt>%x:%x:%x:%x:%x:%x</tt></td>\n",
         b->u.host.mac_addr[0],
         b->u.host.mac_addr[1],
         b->u.host.mac_addr[2],
         b->u.host.mac_addr[3],
         b->u.host.mac_addr[4],
         b->u.host.mac_addr[5]);

   str_appendf(buf,
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n",
      (qu)b->in,
      (qu)b->out,
      (qu)b->total);

   if (opt_want_lastseen) {
      int64_t last = b->u.host.last_seen_mono;
      int64_t now = (int64_t)now_mono();
      struct str *last_str = NULL;

      if ((now >= last) && (last != 0))
         last_str = length_of_time(now - last);

      str_append(buf, " <td class=\"num\">");
      if (last_str == NULL) {
         if (last == 0)
            str_append(buf, "(never)");
         else
            str_appendf(buf, "(clock error: last = %qd, now = %qu)",
                        (qd)last,
                        (qu)now);
      } else {
         str_appendstr(buf, last_str);
         str_free(last_str);
      }
      str_append(buf, "</td>");
   }

   str_appendf(buf, "</tr>\n");

   /* Only resolve hosts "on demand" */
   if (b->u.host.dns == NULL)
      dns_queue(&(b->u.host.addr));
}

static void
format_cols_port_tcp(struct str *buf)
{
   str_append(buf,
      "<table>\n"
      "<tr>\n"
      " <th>Port</td>\n"
      " <th>Service</td>\n"
      " <th>In</td>\n"
      " <th>Out</td>\n"
      " <th>Total</td>\n"
      " <th>SYNs</td>\n"
      "</tr>\n"
   );
}

static void
format_row_port_tcp(struct str *buf, const struct bucket *b)
{
   const struct port_tcp *p = &(b->u.port_tcp);

   str_appendf(buf,
      "<tr>\n"
      " <td class=\"num\">%u</td>\n"
      " <td>%s</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      "</tr>\n",
      p->port,
      getservtcp(p->port),
      (qu)b->in,
      (qu)b->out,
      (qu)b->total,
      (qu)p->syn
   );
}

static void
format_cols_port_udp(struct str *buf)
{
   str_append(buf,
      "<table>\n"
      "<tr>\n"
      " <th>Port</td>\n"
      " <th>Service</td>\n"
      " <th>In</td>\n"
      " <th>Out</td>\n"
      " <th>Total</td>\n"
      "</tr>\n"
   );
}

static void
format_row_port_udp(struct str *buf, const struct bucket *b)
{
   const struct port_udp *p = &(b->u.port_udp);

   str_appendf(buf,
      "<tr>\n"
      " <td class=\"num\">%u</td>\n"
      " <td>%s</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      "</tr>\n",
      p->port,
      getservudp(p->port),
      (qu)b->in,
      (qu)b->out,
      (qu)b->total
   );
}

static void
format_cols_ip_proto(struct str *buf)
{
   str_append(buf,
      "<table>\n"
      "<tr>\n"
      " <th>#</td>\n"
      " <th>Protocol</td>\n"
      " <th>In</td>\n"
      " <th>Out</td>\n"
      " <th>Total</td>\n"
      "</tr>\n"
   );
}

static void
format_row_ip_proto(struct str *buf, const struct bucket *b)
{
   const struct ip_proto *p = &(b->u.ip_proto);

   str_appendf(buf,
      "<tr>\n"
      " <td class=\"num\">%u</td>\n"
      " <td>%s</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      " <td class=\"num\">%'qu</td>\n"
      "</tr>\n",
      p->proto,
      getproto(p->proto),
      (qu)b->in,
      (qu)b->out,
      (qu)b->total
   );
}

/* As there might be multiple rows per peer, the standard CSS pattern
 * does not work for the peers table and we set it manually via
 * a class based on row_peer_port_odd */
static int row_peer_port_odd;

static void
format_cols_peer(struct str *buf)
{
   row_peer_port_odd = 1;

   str_append(buf,
      "<table>\n"
      "<tr>\n"
      " <th>IP</th>\n"
      " <th>Hostname</th>\n"
      " <th>Port</th>\n"
      " <th>Service</th>\n"
      " <th></th>\n"
      " <th>Local port</th>\n"
      " <th>Service</th>\n"
      " <th>In</th>\n"
      " <th>Out</th>\n"
      " <th>Total</th>\n"
      "</tr>\n"
   );
}

static size_t
format_rows_peer_port(struct str *buf,
   const char *addr, const char *hostname,
   struct hashtable *const *pht, int index)
{
   unsigned int i;
   static const char c_multiple[] = "multiple";
   struct bucket *b;
   uint16_t port;
   const struct hashtable *ht = pht[index];
   int tcp     = index == PEER_PORT_TCP || index == PEER_PORT_TCP_PEER;
   int remote  = index == PEER_PORT_TCP_PEER || index == PEER_PORT_UDP_PEER;
   char *proto = tcp ? "tcp" : "udp";
   size_t lines = 0;
   
   if ((ht == NULL) || (ht->count == 0))
      return 0;

   for (i=0; i<ht->size; i++) {
      for (b = ht->table[i]; b; b = b->next) {
         if (b->u.peer_port.hidden) 
            continue;

         str_appendf(buf, "<tr class=\"%s\">\n",
                          row_peer_port_odd ? "odd" : "even");

         if (addr)
            str_appendf(buf, 
               " <td><a href=\"/hosts/%s\">%s</a></td>\n"
               " <td>%s</td>\n",
               addr,
               addr,
               hostname);

         port = remote ?  b->u.peer_port.port_peer : b->u.peer_port.port;
         if (port)
            str_appendf(buf, " <td class=\"num\">%u</td>\n"
                             " <td>%s</td>\n",
                             port,
                             tcp ? getservtcp(port) : getservudp(port));
         else
            str_appendf(buf, " <td>%s</td>\n"
                             " <td></td>\n",
                             c_multiple);

         str_appendf(buf, " <td>%s</td>\n", proto);

         port = !remote ?  b->u.peer_port.port_peer : b->u.peer_port.port;
         if (port)
            str_appendf(buf, " <td class=\"num\">%u</td>\n"
                             " <td>%s</td>\n",
                             port,
                             tcp ? getservtcp(port) : getservudp(port));
         else
            str_appendf(buf, " <td>%s</td>\n"
                             " <td></td>\n",
                             c_multiple);

         str_appendf(buf,
            " <td class=\"num\">%'qu</td>\n"
            " <td class=\"num\">%'qu</td>\n"
            " <td class=\"num\">%'qu</td>\n"
            "</tr>\n",
            (qu)b->in,
            (qu)b->out,
            (qu)b->total
          );
         lines++;
      }
   }
   return lines;
}

static void
format_row_peer(struct str *buf, const struct bucket *b)
{
   const struct peer *p = &(b->u.peer);
   const char *addr = addr_to_str(&(b->u.peer.addr));

   char* hostname = "";
   struct bucket *h = host_find(&(b->u.peer.addr));

   size_t lines = 0;
   size_t pos_rowspan[2] = { 0, 0 }, i;

   /* Get hostname from host DB */
   if (h) {
      if (h->u.host.dns)
         hostname = h->u.host.dns;
      else {
         dns_queue(&(b->u.peer.addr));
         hostname = "(resolving ...)";
      }
   }

   if (p->ports[PEER_PORT_TCP])
      lines += p->ports[PEER_PORT_TCP]->count;
   if (p->ports[PEER_PORT_UDP])
      lines += p->ports[PEER_PORT_UDP]->count;

   if (lines > 1) {
      /* Summary line for multiple ports
       * Save position of the rowspan attributes
       * as we still don't know how may entries we will have */
      str_appendf(buf,
         "<tr class=\"%s\">\n"
         " <td rowspan=\"",
         row_peer_port_odd ? "odd" : "even");
      pos_rowspan[0] = str_len(buf);
      str_appendf(buf,   "1\"      ><a href=\"/hosts/%s\">%s</a></td>\n"
         " <td rowspan=\"",
         addr, addr);
      pos_rowspan[1] = str_len(buf);
      str_appendf(buf,   "1\"      >%s</td>\n"
         " <td colspan=\"5\">&nbsp;</td>\n"
         " <td class=\"num\">%'qu</td>\n"
         " <td class=\"num\">%'qu</td>\n"
         " <td class=\"num\">%'qu</td>\n"
         "</tr>\n",
         hostname,
         (qu)b->in,
         (qu)b->out,
         (qu)b->total
      );
      addr = NULL;

      lines = 1;
   } else
      lines = 0;

   lines += format_rows_peer_port(buf, addr, hostname, p->ports, PEER_PORT_TCP);
   lines += format_rows_peer_port(buf, addr, hostname, p->ports, PEER_PORT_TCP_PEER);
   lines += format_rows_peer_port(buf, addr, hostname, p->ports, PEER_PORT_UDP);
   lines += format_rows_peer_port(buf, addr, hostname, p->ports, PEER_PORT_UDP_PEER);

   /* Adjust the rowspans */
   for (i = 0; i < sizeof(pos_rowspan) / sizeof(pos_rowspan[i]); i++)
      if (pos_rowspan[i])
           str_printf_at(buf, pos_rowspan[i], "%u\"", lines);

   row_peer_port_odd = !row_peer_port_odd;
}

/* ---------------------------------------------------------------------------
 * Initialise a hashtable.
 */
static struct hashtable *
hashtable_make(const uint8_t bits,
   const unsigned int count_max,
   const unsigned int count_keep,
   hash_func_t *hash_func,
   free_func_t *free_func,
   key_func_t *key_func,
   find_func_t *find_func,
   make_func_t *make_func,
   format_cols_func_t *format_cols_func,
   format_row_func_t *format_row_func)
{
   struct hashtable *hash;
   assert(bits > 0);

   hash = xmalloc(sizeof(*hash));
   hash->bits = bits;
   hash->count_max = count_max;
   hash->count_keep = count_keep;
   hash->size = 1U << bits;
   hash->mask = hash->size - 1;
   hash->coeff = coprime(hash->size);
   hash->hash_func = hash_func;
   hash->free_func = free_func;
   hash->key_func = key_func;
   hash->find_func = find_func;
   hash->make_func = make_func;
   hash->format_cols_func = format_cols_func;
   hash->format_row_func = format_row_func;
   hash->count = 0;
   hash->table = xcalloc(hash->size, sizeof(*hash->table));
   memset(&(hash->stats), 0, sizeof(hash->stats));
   return (hash);
}

/* ---------------------------------------------------------------------------
 * Initialise global hosts_db.
 */
void
hosts_db_init(void)
{
   assert(hosts_db == NULL);
   hosts_db = hashtable_make(HOST_BITS, opt_hosts_max, opt_hosts_keep,
      hash_func_host, free_func_host, key_func_host, find_func_host,
      make_func_host, format_cols_host, format_row_host);
}

static void
hashtable_rehash(struct hashtable *h, const uint8_t bits)
{
   struct bucket **old_table, **new_table;
   uint32_t i, old_size;
   assert(h != NULL);
   assert(bits > 0);

   h->stats.rehashes++;
   old_size = h->size;
   old_table = h->table;

   h->bits = bits;
   h->size = 1U << bits;
   h->mask = h->size - 1;
   h->coeff = coprime(h->size);
   new_table = xcalloc(h->size, sizeof(*new_table));

   for (i=0; i<old_size; i++) {
      struct bucket *next, *b = old_table[i];
      while (b != NULL) {
         uint32_t pos = h->hash_func(h, h->key_func(b)) & h->mask;
         next = b->next;
         b->next = new_table[pos];
         new_table[pos] = b;
         b = next;
      }
   }

   free(h->table);
   h->table = new_table;
}

static void
hashtable_insert(struct hashtable *h, struct bucket *b)
{
   uint32_t pos;
   assert(h != NULL);
   assert(b != NULL);
   assert(b->next == NULL);

   /* Rehash on 80% occupancy */
   if ((h->count > h->size) ||
       ((h->size - h->count) < h->size / 5))
      hashtable_rehash(h, h->bits+1);

   pos = h->hash_func(h, h->key_func(b)) & h->mask;
   if (h->table[pos] == NULL)
      h->table[pos] = b;
   else {
      /* Insert at top of chain. */
      b->next = h->table[pos];
      h->table[pos] = b;
   }
   h->count++;
   h->stats.inserts++;
}

/* Return bucket matching key, or NULL if no such entry. */
static struct bucket *
hashtable_search(struct hashtable *h, const void *key)
{
   uint32_t pos;
   struct bucket *b;

   h->stats.searches++;
   pos = h->hash_func(h, key) & h->mask;
   b = h->table[pos];
   while (b != NULL) {
      if (h->find_func(b, key))
         return (b);
      else
         b = b->next;
   }
   return (NULL);
}

typedef enum { NO_REDUCE = 0, ALLOW_REDUCE = 1 } reduce_bool;
/* Search for a key.  If it's not there, make and insert a bucket for it. */
static struct bucket *
hashtable_find_or_insert(struct hashtable *h, const void *key,
      const reduce_bool allow_reduce)
{
   struct bucket *b = hashtable_search(h, key);

   if (b == NULL) {
      /* Not found, so insert after checking occupancy. */
      if (allow_reduce && (h->count >= h->count_max))
         hashtable_reduce(h);
      b = h->make_func(key);
      hashtable_insert(h, b);
   }
   return (b);
}

/*
 * Frees the hashtable and the buckets.  The contents are assumed to be
 * "simple" -- i.e. no "destructor" action is required beyond simply freeing
 * the bucket.
 */
static void
hashtable_free(struct hashtable *h)
{
   uint32_t i;

   if (h == NULL)
      return;
   for (i=0; i<h->size; i++) {
      struct bucket *tmp, *b = h->table[i];
      while (b != NULL) {
         tmp = b;
         b = b->next;
         h->free_func(tmp);
         free(tmp);
      }
   }
   free(h->table);
   free(h);
}

/* ---------------------------------------------------------------------------
 * Return existing host or insert a new one.
 */
struct bucket *
host_get(const struct addr *const a)
{
   return (hashtable_find_or_insert(hosts_db, a, NO_REDUCE));
}

/* ---------------------------------------------------------------------------
 * Find host, returns NULL if not in DB.
 */
struct bucket *
host_find(const struct addr *const a)
{
   return (hashtable_search(hosts_db, a));
}

/* ---------------------------------------------------------------------------
 * Find host, returns NULL if not in DB.
 */
static struct bucket *
host_search(const char *ipstr)
{
   struct addr a;
   struct addrinfo hints, *ai;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_flags = AI_NUMERICHOST;

   if (getaddrinfo(ipstr, NULL, &hints, &ai))
      return (NULL); /* invalid addr */

   if (ai->ai_family == AF_INET) {
      a.family = IPv4;
      a.ip.v4 = ((const struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
   }
   else if (ai->ai_family == AF_INET6) {
      a.family = IPv6;
      memcpy(&(a.ip.v6),
             ((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr.s6_addr,
             sizeof(a.ip.v6));
   } else {
      freeaddrinfo(ai);
      return (NULL); /* unknown family */
   }
   freeaddrinfo(ai);

   verbosef("search(%s) turned into %s", ipstr, addr_to_str(&a));
   return (hashtable_search(hosts_db, &a));
}

/* ---------------------------------------------------------------------------
 * Reduce a hashtable to the top <keep> entries.
 */
static void
hashtable_reduce(struct hashtable *ht)
{
   uint32_t i, pos, rmd;
   const struct bucket **table;
   uint64_t cutoff;

   assert(ht->count_keep < ht->count);

   /* Fill table with pointers to buckets in hashtable. */
   table = xcalloc(ht->count, sizeof(*table));
   for (pos=0, i=0; i<ht->size; i++) {
      struct bucket *b = ht->table[i];
      while (b != NULL) {
         table[pos++] = b;
         b = b->next;
      }
   }
   assert(pos == ht->count);
   qsort_buckets(table, ht->count, 0, ht->count_keep, TOTAL);
   cutoff = table[ht->count_keep]->total;
   free(table);

   /* Remove all elements with total <= cutoff. */
   rmd = 0;
   for (i=0; i<ht->size; i++) {
      struct bucket *last = NULL, *next, *b = ht->table[i];
      while (b != NULL) {
         next = b->next;
         if (b->total <= cutoff) {
            /* Remove this one. */
            ht->free_func(b);
            free(b);
            if (last == NULL)
               ht->table[i] = next;
            else
               last->next = next;
            rmd++;
            ht->count--;
         } else {
            last = b;
         }
         b = next;
      }
   }
   verbosef("hashtable_reduce: removed %u buckets, left %u",
      rmd, ht->count);
   hashtable_rehash(ht, ht->bits); /* is this needed? */
}

/* Reduce hosts_db if needed. */
void hosts_db_reduce(void)
{
   if (hosts_db->count >= hosts_db->count_max)
      hashtable_reduce(hosts_db);
}

/* ---------------------------------------------------------------------------
 * Reset hosts_db to empty.
 */
void
hosts_db_reset(void)
{
   unsigned int i;

   for (i=0; i<hosts_db->size; i++) {
      struct bucket *next, *b = hosts_db->table[i];
      while (b != NULL) {
         next = b->next;
         hosts_db->free_func(b);
         free(b);
         b = next;
      }
      hosts_db->table[i] = NULL;
   }
   verbosef("hosts_db reset to empty, freed %u hosts", hosts_db->count);
   hosts_db->count = 0;
}

/* ---------------------------------------------------------------------------
 * Deallocate hosts_db.
 */
void hosts_db_free(void)
{
   uint32_t i;

   assert(hosts_db != NULL);
   for (i=0; i<hosts_db->size; i++) {
      struct bucket *tmp, *b = hosts_db->table[i];
      while (b != NULL) {
         tmp = b;
         b = b->next;
         hosts_db->free_func(tmp);
         free(tmp);
      }
   }
   free(hosts_db->table);
   free(hosts_db);
   hosts_db = NULL;
}

/* ---------------------------------------------------------------------------
 * Find or create a port_tcp inside a host.
 */
struct bucket *
host_get_port_tcp(struct bucket *host, const uint16_t port)
{
   struct host *h = &host->u.host;
   if (h->ports_tcp == NULL)
      h->ports_tcp = hashtable_make(PORT_BITS, opt_ports_max, opt_ports_keep,
         hash_func_short, free_func_simple, key_func_port_tcp,
         find_func_port_tcp, make_func_port_tcp,
         format_cols_port_tcp, format_row_port_tcp);
   return (hashtable_find_or_insert(h->ports_tcp, &port, ALLOW_REDUCE));
}

struct bucket *
host_get_port_tcp_remote(struct bucket *host, const uint16_t port)
{
   struct host *h = &host->u.host;
   if (h->ports_tcp_remote == NULL)
      h->ports_tcp_remote = hashtable_make(
          PORT_BITS, opt_ports_max, opt_ports_keep, hash_func_short,
          free_func_simple, key_func_port_tcp, find_func_port_tcp,
          make_func_port_tcp, format_cols_port_tcp, format_row_port_tcp);
   return (hashtable_find_or_insert(h->ports_tcp_remote, &port, ALLOW_REDUCE));
}

/* ---------------------------------------------------------------------------
 * Find or create a port_udp inside a host.
 */
struct bucket *
host_get_port_udp(struct bucket *host, const uint16_t port)
{
   struct host *h = &host->u.host;
   if (h->ports_udp == NULL)
      h->ports_udp = hashtable_make(PORT_BITS, opt_ports_max, opt_ports_keep,
         hash_func_short, free_func_simple, key_func_port_udp,
         find_func_port_udp, make_func_port_udp,
         format_cols_port_udp, format_row_port_udp);
   return (hashtable_find_or_insert(h->ports_udp, &port, ALLOW_REDUCE));
}

struct bucket *
host_get_port_udp_remote(struct bucket *host, const uint16_t port)
{
   struct host *h = &host->u.host;
   if (h->ports_udp_remote == NULL)
      h->ports_udp_remote = hashtable_make(
          PORT_BITS, opt_ports_max, opt_ports_keep, hash_func_short,
          free_func_simple, key_func_port_udp, find_func_port_udp,
          make_func_port_udp, format_cols_port_udp, format_row_port_udp);
   return (hashtable_find_or_insert(h->ports_udp_remote, &port, ALLOW_REDUCE));
}

/* ---------------------------------------------------------------------------
 * Find or create an ip_proto inside a host.
 */
struct bucket *
host_get_ip_proto(struct bucket *host, const uint8_t proto)
{
   struct host *h = &host->u.host;
   static const unsigned int PROTOS_MAX = 512, PROTOS_KEEP = 256;
   assert(h != NULL);
   if (h->ip_protos == NULL)
      h->ip_protos = hashtable_make(PROTO_BITS, PROTOS_MAX, PROTOS_KEEP,
         hash_func_byte, free_func_simple, key_func_ip_proto,
         find_func_ip_proto, make_func_ip_proto,
         format_cols_ip_proto, format_row_ip_proto);
   return (hashtable_find_or_insert(h->ip_protos, &proto, ALLOW_REDUCE));
}

static struct str *html_hosts_main(const char *qs);
static struct str *html_hosts_detail(const char *ip);

/* ---------------------------------------------------------------------------
 * Find or create peer inside a host
 */
struct bucket *
host_get_peer(struct bucket *host, const struct addr *const a)
{
   struct host *h = &host->u.host;
   if (h->peers == NULL)
      h->peers = hashtable_make(
          HOST_BITS, opt_peers_max, opt_peers_keep, hash_func_host,
          free_func_peer, key_func_host, find_func_host,
          make_func_peer, format_cols_peer, format_row_peer);
   return (hashtable_find_or_insert(h->peers, a, ALLOW_REDUCE));
}

struct bucket *
peer_find_port(struct hashtable *table, uint16_t port)
{
    if (!table)
        return NULL;
    
    return (hashtable_search(table, &port));
}

struct bucket *
peer_get_port(struct hashtable **table, uint16_t port)
{
   if (*table == NULL)
      *table = hashtable_make(
          PORT_BITS, opt_ports_max, opt_ports_keep, hash_func_short,
          free_func_simple, key_func_peer_port, find_func_peer_port,
          make_func_peer_port, NULL, NULL);

    return (hashtable_find_or_insert(*table, &port, ALLOW_REDUCE));
}

/* ---------------------------------------------------------------------------
 * Web interface: delegate the /hosts/ space.
 */
struct str *
html_hosts(const char *uri, const char *query)
{
   unsigned int i, num_elems;
   char **elem = split('/', uri, &num_elems);
   struct str *buf = NULL;

   assert(num_elems >= 1);
   assert(strcmp(elem[0], "hosts") == 0);

   if (num_elems == 1)
      /* /hosts/ */
      buf = html_hosts_main(query);
   else if (num_elems == 2)
      /* /hosts/<IP of host>/ */
      buf = html_hosts_detail(elem[1]);

   for (i=0; i<num_elems; i++)
      free(elem[i]);
   free(elem);
   return (buf); /* FIXME: a NULL here becomes 404 Not Found, we might want
   other codes to be possible */
}

/* ---------------------------------------------------------------------------
 * Get an array of pointers to all the buckets in the hashtable,
 * or NULL if the hashtable is NULL or empty.
 * The returned pointer should be free'd by the caller.
 */
const struct bucket **
hashtable_list_buckets(struct hashtable *ht)
{
   const struct bucket **table;
   unsigned int i, pos;

   if ((ht == NULL) || (ht->count == 0)) {
      return NULL;
   }

   /* Fill table with pointers to buckets in hashtable. */
   table = xcalloc(ht->count, sizeof(*table));
   for (pos=0, i=0; i<ht->size; i++) {
      struct bucket *b = ht->table[i];
      while (b != NULL) {
         table[pos++] = b;
         b = b->next;
      }
   }
   assert(pos == ht->count);
   return table;
}

typedef void (hashtable_foreach_func_t)(const struct bucket *, const void *);

/* ---------------------------------------------------------------------------
 * Loop over all buckets in the given hashtable, calling the supplied function
 * with each bucket and the supplied user_data.
 */
static void
hashtable_foreach(struct hashtable *ht,
   hashtable_foreach_func_t *hashtable_foreach_func,
   const void *user_data)
{
   const struct bucket **table;
   unsigned int i;

   table = hashtable_list_buckets(ht);
   if (table == NULL)
      return;

   for (i = 0; i<ht->count; i++) {
      const struct bucket *b = table[i];
      (*hashtable_foreach_func)(b, user_data);
   }
   free(table);
}

/* ---------------------------------------------------------------------------
 * Format hashtable into HTML.
 */
static void
format_table(struct str *buf, struct hashtable *ht, unsigned int start,
   const enum sort_dir sort, const int full)
{
   const struct bucket **table;
   unsigned int i, end;
   int alt = 0;

   table = hashtable_list_buckets(ht);

   if (table == NULL) {
      str_append(buf, "<p>The table is empty.</p>\n");
      return;
   }

   if (full) {
      /* full report overrides start and end */
      start = 0;
      end = ht->count;
   } else
      end = MIN(ht->count, (uint32_t)start+MAX_ENTRIES);

   str_appendf(buf, "(%u-%u of %u)<br>\n", start+1, end, ht->count);
   qsort_buckets(table, ht->count, start, end, sort);
   ht->format_cols_func(buf);

   for (i=start; i<end; i++) {
      ht->format_row_func(buf, table[i]);
      alt = !alt; /* alternate class for table rows */
   }
   free(table);
   str_append(buf, "</table>\n");
}

/* ---------------------------------------------------------------------------
 * Web interface: sorted table of hosts.
 */
static struct str *
html_hosts_main(const char *qs)
{
   struct str *buf = str_make();
   char *qs_start, *qs_sort, *qs_full, *ep;
   const char *sortstr;
   int start, full = 0;
   enum sort_dir sort;

   /* parse query string */
   qs_start = qs_get(qs, "start");
   qs_sort = qs_get(qs, "sort");
   qs_full = qs_get(qs, "full");
   if (qs_full != NULL) {
      full = 1;
      free(qs_full);
   }

   /* validate sort */
   if (qs_sort == NULL) sort = TOTAL;
   else if (strcmp(qs_sort, "total") == 0) sort = TOTAL;
   else if (strcmp(qs_sort, "in") == 0) sort = IN;
   else if (strcmp(qs_sort, "out") == 0) sort = OUT;
   else if (strcmp(qs_sort, "lastseen") == 0) sort = LASTSEEN;
   else {
      str_append(buf, "Error: invalid value for \"sort\".\n");
      goto done;
   }

   /* parse start */
   if (qs_start == NULL)
      start = 0;
   else {
      start = (int)strtoul(qs_start, &ep, 10);
      if (*ep != '\0') {
         str_append(buf, "Error: \"start\" is not a number.\n");
         goto done;
      }
      if ((errno == ERANGE) ||
          (start < 0) || (start >= (int)hosts_db->count)) {
         str_append(buf, "Error: \"start\" is out of bounds.\n");
         goto done;
      }
   }

#define PREV "&lt;&lt;&lt; prev page"
#define NEXT "next page &gt;&gt;&gt;"
#define FULL "full table"

   html_open(buf, "Hosts", /*path_depth=*/1, /*want_graph_js=*/0);
   format_table(buf, hosts_db, start, sort, full);

   /* <prev | full | stats | next> */
   sortstr = qs_sort;
   if (sortstr == NULL) sortstr = "total";
   if (start > 0) {
      int prev = start - MAX_ENTRIES;
      if (prev < 0)
         prev = 0;
      str_appendf(buf, "<a href=\"?start=%d&sort=%s\">" PREV "</a>",
         prev, sortstr);
   } else
      str_append(buf, PREV);

   if (full)
      str_append(buf, " | " FULL);
   else
      str_appendf(buf, " | <a href=\"?full=yes&sort=%s\">" FULL "</a>",
         sortstr);

   if (start+MAX_ENTRIES < (int)hosts_db->count)
      str_appendf(buf, " | <a href=\"?start=%d&sort=%s\">" NEXT "</a>",
         start+MAX_ENTRIES, sortstr);
   else
      str_append(buf, " | " NEXT);

   str_append(buf, "<br>\n");

   html_close(buf);
done:
   if (qs_start != NULL) free(qs_start);
   if (qs_sort != NULL) free(qs_sort);
   return buf;
#undef PREV
#undef NEXT
#undef FULL
}

/* ---------------------------------------------------------------------------
 * Web interface: detailed view of a single host.
 */
static struct str *html_hosts_detail(const char *ip) {
   struct bucket *h;
   struct str *buf, *ls_len;
   char ls_when[100];
   const char *canonical;
   time_t last_seen_real;

   h = host_search(ip);
   if (h == NULL)
      return (NULL); /* no such host */

   canonical = addr_to_str(&(h->u.host.addr));

   /* Overview. */
   buf = str_make();
   html_open(buf, ip, /*path_depth=*/2, /*want_graph_js=*/0);
   if (strcmp(ip, canonical) != 0)
      str_appendf(buf, "(canonically <b>%s</b>)\n", canonical);
   str_appendf(buf,
      "<p>\n"
       "<b>Hostname:</b> %s<br>\n",
      (h->u.host.dns == NULL)?"(resolving...)":h->u.host.dns);

   /* Resolve host "on demand" */
   if (h->u.host.dns == NULL)
      dns_queue(&(h->u.host.addr));

   if (hosts_db_show_macs)
      str_appendf(buf,
         "<b>MAC Address:</b> "
         "<tt>%x:%x:%x:%x:%x:%x</tt><br>\n",
         h->u.host.mac_addr[0],
         h->u.host.mac_addr[1],
         h->u.host.mac_addr[2],
         h->u.host.mac_addr[3],
         h->u.host.mac_addr[4],
         h->u.host.mac_addr[5]);

   str_append(buf,
      "</p>\n"
      "<p>\n"
      "<b>Last seen:</b> ");

   if (h->u.host.last_seen_mono == 0) {
      str_append(buf, "(never)");
   } else {
      last_seen_real = mono_to_real(h->u.host.last_seen_mono);
      if (strftime(ls_when, sizeof(ls_when),
         "%Y-%m-%d %H:%M:%S %Z%z", localtime(&last_seen_real)) != 0)
            str_append(buf, ls_when);

      if (h->u.host.last_seen_mono <= now_mono()) {
         ls_len =
             length_of_time((int64_t)now_mono() - h->u.host.last_seen_mono);
         str_append(buf, " (");
         str_appendstr(buf, ls_len);
         str_free(ls_len);
         str_append(buf, " ago)");
      } else {
         str_appendf(buf, " (in the future, possible clock problem, "
                     "last = %qd, now = %qu)",
                     (qd)h->u.host.last_seen_mono,
                     (qu)now_mono());
      }
  }

   str_appendf(buf,
      "</p>\n"
      "<p>\n"
      " <b>In:</b> %'qu<br>\n"
      " <b>Out:</b> %'qu<br>\n"
      " <b>Total:</b> %'qu<br>\n"
      "</p>\n",
      (qu)h->in,
      (qu)h->out,
      (qu)h->total);

   if (h->u.host.peers) {
      str_append(buf, "<h3>Peers</h3>\n");
      format_table(buf, h->u.host.peers, 0,TOTAL,1);
   }

   if (h->u.host.ports_tcp) {
      str_append(buf, "<h3>TCP ports on this host</h3>\n");
      format_table(buf, h->u.host.ports_tcp, 0,TOTAL,0);
   }

   if (h->u.host.ports_tcp_remote) {
      str_append(buf, "<h3>TCP ports on remote hosts</h3>\n");
      format_table(buf, h->u.host.ports_tcp_remote, 0,TOTAL,0);
   }

   if (h->u.host.ports_udp) {
      str_append(buf, "<h3>UDP ports on this host</h3>\n");
      format_table(buf, h->u.host.ports_udp, 0,TOTAL,0);
   }

   if (h->u.host.ports_udp_remote) {
      str_append(buf, "<h3>UDP ports on remote hosts</h3>\n");
      format_table(buf, h->u.host.ports_udp_remote, 0,TOTAL,0);
   }

   if (h->u.host.ip_protos) {
      str_append(buf, "<h3>IP protocols</h3>\n");
      format_table(buf, h->u.host.ip_protos, 0,TOTAL,0);
   }

   str_append(buf, "<br>\n");
   html_close(buf);
   return buf;
}

/* ---------------------------------------------------------------------------
 * Database import and export code:
 * Initially written and contributed by Ben Stewart.
 * copyright (c) 2007-2014 Ben Stewart, Emil Mikulic.
 */
static int hosts_db_export_ip(const struct hashtable *h, const int fd);
static int hosts_db_export_tcp(const char magic, const struct hashtable *h,
                               const int fd);
static int hosts_db_export_udp(const char magic, const struct hashtable *h,
                               const int fd);

static const char
   export_proto_ip         = 'P',
   export_proto_tcp        = 'T',
   export_proto_tcp_remote = 't',
   export_proto_udp        = 'U',
   export_proto_udp_remote = 'u';

static const unsigned char
   export_tag_host_ver1[] = {'H', 'S', 'T', 0x01},
   export_tag_host_ver2[] = {'H', 'S', 'T', 0x02},
   export_tag_host_ver3[] = {'H', 'S', 'T', 0x03},
   export_tag_host_ver4[] = {'H', 'S', 'T', 0x04};

static void text_metrics_counter(struct str *buf, const char *metric, const char *type, const char *help);
static void text_metrics_format_host(const struct bucket *b, const void *user_data);

/* ---------------------------------------------------------------------------
 * Web interface: export stats in Prometheus text format on /metrics
 */
struct str *
text_metrics()
{
   struct str *buf = str_make();

   text_metrics_counter(buf,
      "host_bytes_total",
      "counter",
      "Total number of network bytes by host and direction.");
   hashtable_foreach(hosts_db, &text_metrics_format_host, (void *)buf);

   return buf;
}

static void
text_metrics_counter(struct str *buf,
   const char *metric,
   const char *type,
   const char *help)
{
   str_appendf(buf, "# HELP %s %s\n", metric, help);
   str_appendf(buf, "# TYPE %s %s\n", metric, type);
}

static void
text_metrics_format_host_key(struct str *buf, const struct bucket *b) {
   const char *ip = addr_to_str(&(b->u.host.addr));

   str_appendf(buf,
      "host_bytes_total{interface=\"%s\",ip=\"%s\"",
      title_interfaces, ip);

   if (hosts_db_show_macs)
      str_appendf(buf, ",mac=\"%x:%x:%x:%x:%x:%x\"",
         b->u.host.mac_addr[0],
         b->u.host.mac_addr[1],
         b->u.host.mac_addr[2],
         b->u.host.mac_addr[3],
         b->u.host.mac_addr[4],
         b->u.host.mac_addr[5]);
}

static void
text_metrics_format_host(const struct bucket *b,
   const void *user_data)
{
   struct str *buf = (struct str *)user_data;

   text_metrics_format_host_key(buf, b);
   str_appendf(buf, ",dir=\"in\"} %qu\n", (qu)b->in);

   text_metrics_format_host_key(buf, b);
   str_appendf(buf, ",dir=\"out\"} %qu\n", (qu)b->out);
}

/* ---------------------------------------------------------------------------
 * Load a host's ip_proto table from a file.
 * Returns 0 on failure, 1 on success.
 */
static int
hosts_db_import_ip(const int fd, struct bucket *host)
{
   uint8_t count, i;

   if (!expect8(fd, export_proto_ip)) return 0;
   if (!read8(fd, &count)) return 0;

   for (i=0; i<count; i++) {
      struct bucket *b;
      uint8_t proto;
      uint64_t in, out;

      if (!read8(fd, &proto)) return 0;
      if (!read64(fd, &in)) return 0;
      if (!read64(fd, &out)) return 0;

      /* Store data */
      b = host_get_ip_proto(host, proto);
      b->in = in;
      b->out = out;
      b->total = in + out;
      assert(b->u.ip_proto.proto == proto); /* should be done by make fn */
   }
   return 1;
}

/* ---------------------------------------------------------------------------
 * Load a host's port_tcp{,_remote} table from a file.
 * Returns 0 on failure, 1 on success.
 */
static int hosts_db_import_tcp(const int fd, const char magic,
                               struct bucket *host,
                               struct bucket *(get_port_fn)(struct bucket *host,
                                                            uint16_t port)) {
   uint16_t count, i;

   if (!expect8(fd, magic)) return 0;
   if (!read16(fd, &count)) return 0;

   for (i=0; i<count; i++) {
      struct bucket *b;
      uint16_t port;
      uint64_t in, out, syn;

      if (!read16(fd, &port)) return 0;
      if (!read64(fd, &syn)) return 0;
      if (!read64(fd, &in)) return 0;
      if (!read64(fd, &out)) return 0;

      /* Store data */
      b = get_port_fn(host, port);
      b->in = in;
      b->out = out;
      b->total = in + out;
      assert(b->u.port_tcp.port == port); /* done by make_func_port_tcp */
      b->u.port_tcp.syn = syn;
   }
   return 1;
}

/* ---------------------------------------------------------------------------
 * Load a host's port_tcp table from a file.
 * Returns 0 on failure, 1 on success.
 */
static int hosts_db_import_udp(const int fd, const char magic,
                               struct bucket *host,
                               struct bucket *(get_port_fn)(struct bucket *host,
                                                            uint16_t port)) {
   uint16_t count, i;

   if (!expect8(fd, magic)) return 0;
   if (!read16(fd, &count)) return 0;

   for (i=0; i<count; i++) {
      struct bucket *b;
      uint16_t port;
      uint64_t in, out;

      if (!read16(fd, &port)) return 0;
      if (!read64(fd, &in)) return 0;
      if (!read64(fd, &out)) return 0;

      /* Store data */
      b = get_port_fn(host, port);
      b->in = in;
      b->out = out;
      b->total = in + out;
      assert(b->u.port_udp.port == port); /* done by make_func */
   }
   return 1;
}

/* ---------------------------------------------------------------------------
 * Load all hosts from a file.
 * Returns 0 on failure, 1 on success.
 */
static int
hosts_db_import_host(const int fd)
{
   struct bucket *host;
   struct addr a;
   uint8_t hostname_len;
   uint64_t in, out;
   unsigned int pos = xtell(fd);
   char hdr[4];
   int ver = 0;

   if (!readn(fd, hdr, sizeof(hdr))) return 0;
   if (memcmp(hdr, export_tag_host_ver4, sizeof(hdr)) == 0)
      ver = 4;
   else if (memcmp(hdr, export_tag_host_ver3, sizeof(hdr)) == 0)
      ver = 3;
   else if (memcmp(hdr, export_tag_host_ver2, sizeof(hdr)) == 0)
      ver = 2;
   else if (memcmp(hdr, export_tag_host_ver1, sizeof(hdr)) == 0)
      ver = 1;
   else {
      warnx("bad host header: %02x%02x%02x%02x",
         hdr[0], hdr[1], hdr[2], hdr[3]);
      return 0;
   }

   if (ver >= 3) {
      if (!readaddr(fd, &a))
         return 0;
   } else {
      assert((ver == 1) || (ver == 2));
      if (!readaddr_ipv4(fd, &a))
         return 0;
   }
   verbosef("at file pos %u, importing host %s", pos, addr_to_str(&a));
   host = host_get(&a);
   assert(addr_equal(&(host->u.host.addr), &a));

   if (ver > 1) {
      uint64_t t;
      if (!read64(fd, &t)) return 0;
      host->u.host.last_seen_mono = real_to_mono(t);
   }

   assert(sizeof(host->u.host.mac_addr) == 6);
   if (!readn(fd, host->u.host.mac_addr, sizeof(host->u.host.mac_addr)))
      return 0;

   /* HOSTNAME */
   assert(host->u.host.dns == NULL); /* make fn? */
   if (!read8(fd, &hostname_len)) return 0;
   if (hostname_len > 0) {
      host->u.host.dns = xmalloc(hostname_len + 1);
      host->u.host.dns[0] = '\0';

      /* At this point, the hostname is attached to a host which is in our
       * hosts_db, so if we bail out due to an import error, this pointer
       * isn't lost and leaked, it can be cleaned up in hosts_db_{free,reset}
       */

      if (!readn(fd, host->u.host.dns, hostname_len)) return 0;
      host->u.host.dns[hostname_len] = '\0';
   }

   if (!read64(fd, &in)) return 0;
   if (!read64(fd, &out)) return 0;

   host->in = in;
   host->out = out;
   host->total = in + out;

   /* Host's port and proto subtables: */
   if (!hosts_db_import_ip(fd, host)) return 0;
   if (!hosts_db_import_tcp(fd, export_proto_tcp, host, host_get_port_tcp))
      return 0;
   if (!hosts_db_import_udp(fd, export_proto_udp, host, host_get_port_udp))
      return 0;

   if (ver == 4) {
      if (!hosts_db_import_tcp(fd, export_proto_tcp_remote, host,
                               host_get_port_tcp_remote))
         return 0;
      if (!hosts_db_import_udp(fd, export_proto_udp_remote, host,
                               host_get_port_udp_remote))
         return 0;
   }
   return 1;
}

/* ---------------------------------------------------------------------------
 * Database Import: Grab hosts_db from a file provided by the caller.
 *
 * This function will retrieve the data sans the header.  We expect the caller
 * to have validated the header of the hosts_db segment, and left the file
 * sitting at the start of the data.
 */
int hosts_db_import(const int fd)
{
   uint32_t host_count, i;

   if (!read32(fd, &host_count)) return 0;

   for (i=0; i<host_count; i++)
      if (!hosts_db_import_host(fd)) return 0;

   return 1;
}

/* ---------------------------------------------------------------------------
 * Database Export: Dump hosts_db into a file provided by the caller.
 * The caller is responsible for writing out export_tag_hosts_ver1 first.
 */
int hosts_db_export(const int fd)
{
   uint32_t i;
   struct bucket *b;

   if (!write32(fd, hosts_db->count)) return 0;

   for (i = 0; i<hosts_db->size; i++)
   for (b = hosts_db->table[i]; b != NULL; b = b->next) {
      /* For each host: */
      if (!writen(fd, export_tag_host_ver4, sizeof(export_tag_host_ver4)))
         return 0;

      if (!writeaddr(fd, &(b->u.host.addr)))
         return 0;

      if (!write64(fd, (uint64_t)mono_to_real(b->u.host.last_seen_mono)))
         return 0;

      assert(sizeof(b->u.host.mac_addr) == 6);
      if (!writen(fd, b->u.host.mac_addr, sizeof(b->u.host.mac_addr)))
         return 0;

      /* HOSTNAME */
      if (b->u.host.dns == NULL) {
         if (!write8(fd, 0)) return 0;
      } else {
         int dnslen = strlen(b->u.host.dns);

         if (dnslen > 255) {
           warnx("found a very long hostname: \"%s\"\n"
              "wasn't expecting one longer than 255 chars (this one is %d)",
              b->u.host.dns, dnslen);
           dnslen = 255;
         }

         if (!write8(fd, (uint8_t)dnslen)) return 0;
         if (!writen(fd, b->u.host.dns, dnslen)) return 0;
      }

      if (!write64(fd, b->in)) return 0;
      if (!write64(fd, b->out)) return 0;

      if (!hosts_db_export_ip(b->u.host.ip_protos, fd)) return 0;
      if (!hosts_db_export_tcp(export_proto_tcp, b->u.host.ports_tcp, fd))
         return 0;
      if (!hosts_db_export_udp(export_proto_udp, b->u.host.ports_udp, fd))
         return 0;
      if (!hosts_db_export_tcp(export_proto_tcp_remote,
                               b->u.host.ports_tcp_remote, fd))
         return 0;
      if (!hosts_db_export_udp(export_proto_udp_remote,
                               b->u.host.ports_udp_remote, fd))
         return 0;
   }
   return 1;
}

/* ---------------------------------------------------------------------------
 * Dump the ip_proto table of a host.
 */
static int
hosts_db_export_ip(const struct hashtable *h, const int fd)
{
   uint32_t i, written = 0;
   struct bucket *b;

   /* IP DATA */
   if (!write8(fd, export_proto_ip)) return 0;

   /* If no data, write a IP Proto count of 0 and we're done. */
   if (h == NULL) {
      if (!write8(fd, 0)) return 0;
      return 1;
   }

   assert(h->count < 256);
   if (!write8(fd, (uint8_t)h->count)) return 0;

   for (i = 0; i<h->size; i++)
   for (b = h->table[i]; b != NULL; b = b->next) {
      /* For each ip_proto bucket: */

      if (!write8(fd, b->u.ip_proto.proto)) return 0;
      if (!write64(fd, b->in)) return 0;
      if (!write64(fd, b->out)) return 0;
      written++;
   }
   assert(written == h->count);
   return 1;
}

/* ---------------------------------------------------------------------------
 * Dump the port_tcp table of a host.
 */
static int
hosts_db_export_tcp(const char magic, const struct hashtable *h, const int fd)
{
   struct bucket *b;
   uint32_t i, written = 0;

   /* TCP DATA */
   if (!write8(fd, magic)) return 0;

   /* If no data, write a count of 0 and we're done. */
   if (h == NULL) {
      if (!write16(fd, 0)) return 0;
      return 1;
   }

   assert(h->count < 65536);
   if (!write16(fd, (uint16_t)h->count)) return 0;

   for (i = 0; i<h->size; i++)
   for (b = h->table[i]; b != NULL; b = b->next) {
      if (!write16(fd, b->u.port_tcp.port)) return 0;
      if (!write64(fd, b->u.port_tcp.syn)) return 0;
      if (!write64(fd, b->in)) return 0;
      if (!write64(fd, b->out)) return 0;
      written++;
   }
   assert(written == h->count);
   return 1;
}

/* ---------------------------------------------------------------------------
 * Dump the port_udp table of a host.
 */
static int
hosts_db_export_udp(const char magic, const struct hashtable *h, const int fd)
{
   struct bucket *b;
   uint32_t i, written = 0;

   /* UDP DATA */
   if (!write8(fd, magic)) return 0;

   /* If no data, write a count of 0 and we're done. */
   if (h == NULL) {
      if (!write16(fd, 0)) return 0;
      return 1;
   }

   assert(h->count < 65536);
   if (!write16(fd, (uint16_t)h->count)) return 0;

   for (i = 0; i<h->size; i++)
   for (b = h->table[i]; b != NULL; b = b->next) {
      if (!write16(fd, b->u.port_udp.port)) return 0;
      if (!write64(fd, b->in)) return 0;
      if (!write64(fd, b->out)) return 0;
      written++;
   }
   assert(written == h->count);
   return 1;
}

/* vim:set ts=3 sw=3 tw=80 expandtab: */
