/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * ncache.c: cache of protocol and service names.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "conv.h"
#include "err.h"
#include "ncache.h"
#include "tree.h"
#include "bsd.h" /* for strlcpy */

#include <netinet/in.h> /* ntohs */
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

struct name_rec {
   RB_ENTRY(name_rec) ptree;
   int num;
   char *name;
};

static int
rec_cmp(struct name_rec *a, struct name_rec *b)
{
   if (a->num < b->num) return (-1); else
   if (a->num > b->num) return (+1); else
   return (0);
}

RB_HEAD(nc_tree, name_rec);
RB_GENERATE_STATIC(nc_tree, name_rec, ptree, rec_cmp)

static struct nc_tree
   t_proto   = RB_INITIALIZER(&name_rec),
   t_servtcp = RB_INITIALIZER(&name_rec),
   t_servudp = RB_INITIALIZER(&name_rec);

static void
add_rec(struct nc_tree *tree, const int num, const char *name)
{
   struct name_rec *e, *r = xmalloc(sizeof(*r));

   r->num = num;
   e = RB_INSERT(nc_tree, tree, r);

   if (e != NULL) {
      size_t newlen;

      /* record exists: append service name, free record */
      newlen = strlen(e->name) + strlen(name) + 2;
      e->name = xrealloc(e->name, newlen);
      strlcat(e->name, " ", newlen);
      strlcat(e->name, name, newlen);
      free(r);
   }
   else {
      /* record added: fill out name field */
      r->name = xstrdup(name);
   }
}

void
ncache_init(void)
{
   struct protoent *pe;
   struct servent *se;
   int count, ctcp, cudp;

   count = 0;
   setprotoent(0);
   while ((pe = getprotoent()) != NULL) {
      add_rec(&t_proto, pe->p_proto, pe->p_name);
      count++;
   }
   endprotoent();
   verbosef("loaded %d protos", count);

   count = ctcp = cudp = 0;
   setservent(0);
   while ((se = getservent()) != NULL) {
      if (strcmp(se->s_proto, "tcp") == 0) {
         add_rec(&t_servtcp, ntohs(se->s_port), se->s_name);
         ctcp++;
      }
      else if (strcmp(se->s_proto, "udp") == 0) {
         add_rec(&t_servudp, ntohs(se->s_port), se->s_name);
         cudp++;
      }
      count++;
   }
   endservent();
   verbosef("loaded %d tcp and %d udp servs, from total %d",
      ctcp, cudp, count);
}

static void
tree_free(struct nc_tree *tree)
{
   struct name_rec *curr, *next;

   for (curr = RB_MIN(nc_tree, tree); curr != NULL; curr = next) {
      next = RB_NEXT(nc_tree, tree, curr);
      RB_REMOVE(nc_tree, tree, curr);
      free(curr->name);
      free(curr);
   }
}

void
ncache_free(void)
{
   tree_free(&t_proto);
   tree_free(&t_servtcp);
   tree_free(&t_servudp);
}

#define FIND(tree,n) { \
   struct name_rec r, *f; \
   r.num = n; \
   f = RB_FIND(nc_tree, &tree, &r); \
   if (f == NULL) \
      return (""); \
   else \
      return (f->name); \
}

const char *
getproto(const int proto)
FIND(t_proto, proto)

const char *
getservtcp(const int port)
FIND(t_servtcp, port)

const char *
getservudp(const int port)
FIND(t_servudp, port)

/* vim:set ts=3 sw=3 tw=78 expandtab: */
