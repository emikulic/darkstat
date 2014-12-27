/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * dns.c: synchronous DNS in a child process.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "cdefs.h"
#include "cap.h"
#include "conv.h"
#include "decode.h"
#include "dns.h"
#include "err.h"
#include "hosts_db.h"
#include "queue.h"
#include "str.h"
#include "tree.h"
#include "bsd.h" /* for setproctitle, strlcpy */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __NetBSD__
# define gethostbyaddr(addr, len, type) \
         gethostbyaddr((const char *)(addr), len, type)
#endif

static void dns_main(void) _noreturn_; /* the child process runs this */

#define CHILD 0 /* child process uses this socket */
#define PARENT 1
static int dns_sock[2];
static pid_t pid = -1;

struct dns_reply {
   struct addr addr;
   int error; /* for gai_strerror(), or 0 if no error */
   char name[256]; /* http://tools.ietf.org/html/rfc1034#section-3.1 */
};

void
dns_init(const char *privdrop_user)
{
   if (socketpair(AF_UNIX, SOCK_STREAM, 0, dns_sock) == -1)
      err(1, "socketpair");

   pid = fork();
   if (pid == -1)
      err(1, "fork");

   if (pid == 0) {
      /* We are the child. */
      privdrop(NULL /* don't chroot */, privdrop_user);
      close(dns_sock[PARENT]);
      dns_sock[PARENT] = -1;
      daemonize_finish(); /* drop our copy of the lifeline! */
      if (signal(SIGUSR1, SIG_IGN) == SIG_ERR)
         errx(1, "signal(SIGUSR1, ignore) failed");
      cap_free_args();
      dns_main();
      errx(1, "DNS child fell out of dns_main()");
   } else {
      /* We are the parent. */
      close(dns_sock[CHILD]);
      dns_sock[CHILD] = -1;
      fd_set_nonblock(dns_sock[PARENT]);
      verbosef("DNS child has PID %d", pid);
   }
}

void
dns_stop(void)
{
   if (pid == -1)
      return; /* no child was started */
   close(dns_sock[PARENT]);
   if (kill(pid, SIGINT) == -1)
      err(1, "kill");
   verbosef("dns_stop() waiting for child");
   if (waitpid(pid, NULL, 0) == -1)
      err(1, "waitpid");
   verbosef("dns_stop() done waiting for child");
}

struct tree_rec {
   RB_ENTRY(tree_rec) ptree;
   struct addr ip;
};

static int
tree_cmp(struct tree_rec *a, struct tree_rec *b)
{
   if (a->ip.family != b->ip.family)
      /* Sort IPv4 to the left of IPv6.  */
      return ((a->ip.family == IPv4) ? -1 : +1);

   if (a->ip.family == IPv4)
      return (memcmp(&a->ip.ip.v4, &b->ip.ip.v4, sizeof(a->ip.ip.v4)));
   else {
      assert(a->ip.family == IPv6);
      return (memcmp(&a->ip.ip.v6, &b->ip.ip.v6, sizeof(a->ip.ip.v6)));
   }
}

static RB_HEAD(tree_t, tree_rec) ip_tree = RB_INITIALIZER(&tree_rec);
RB_GENERATE_STATIC(tree_t, tree_rec, ptree, tree_cmp)

void
dns_queue(const struct addr *const ipaddr)
{
   struct tree_rec *rec;
   ssize_t num_w;

   if (pid == -1)
      return; /* no child was started - we're not doing any DNS */

   if ((ipaddr->family != IPv4) && (ipaddr->family != IPv6)) {
      verbosef("dns_queue() for unknown family %d", ipaddr->family);
      return;
   }

   rec = xmalloc(sizeof(*rec));
   memcpy(&rec->ip, ipaddr, sizeof(rec->ip));

   if (RB_INSERT(tree_t, &ip_tree, rec) != NULL) {
      /* Already queued - this happens seldom enough that we don't care about
       * the performance hit of needlessly malloc()ing. */
      verbosef("already queued %s", addr_to_str(ipaddr));
      free(rec);
      return;
   }

   num_w = write(dns_sock[PARENT], ipaddr, sizeof(*ipaddr)); /* won't block */
   if (num_w == 0)
      warnx("dns_queue: write: ignoring end of file");
   else if (num_w == -1)
      warn("dns_queue: ignoring write error");
   else if (num_w != sizeof(*ipaddr))
      err(1, "dns_queue: wrote %zu instead of %zu", num_w, sizeof(*ipaddr));
}

static void
dns_unqueue(const struct addr *const ipaddr)
{
   struct tree_rec tmp, *rec;

   memcpy(&tmp.ip, ipaddr, sizeof(tmp.ip));
   if ((rec = RB_FIND(tree_t, &ip_tree, &tmp)) != NULL) {
      RB_REMOVE(tree_t, &ip_tree, rec);
      free(rec);
   }
   else
      verbosef("couldn't unqueue %s - not in queue!", addr_to_str(ipaddr));
}

/*
 * Returns non-zero if result waiting, stores IP and name into given pointers
 * (name buffer is allocated by dns_poll)
 */
static int
dns_get_result(struct addr *ipaddr, char **name)
{
   struct dns_reply reply;
   ssize_t numread;

   numread = read(dns_sock[PARENT], &reply, sizeof(reply));
   if (numread == -1) {
      if (errno == EAGAIN)
         return (0); /* no input waiting */
      else
         goto error;
   }
   if (numread == 0)
      goto error; /* EOF */
   if (numread != sizeof(reply))
      errx(1, "dns_get_result read got %zu, expected %zu",
         numread, sizeof(reply));

   /* Return successful reply. */
   memcpy(ipaddr, &reply.addr, sizeof(*ipaddr));
   if (reply.error != 0) {
      /* Identify common special cases.  */
      const char *type = "none";

      if (reply.addr.family == IPv6) {
         if (IN6_IS_ADDR_LINKLOCAL(&reply.addr.ip.v6))
            type = "link-local";
         else if (IN6_IS_ADDR_SITELOCAL(&reply.addr.ip.v6))
            type = "site-local";
         else if (IN6_IS_ADDR_MULTICAST(&reply.addr.ip.v6))
            type = "multicast";
      } else {
         assert(reply.addr.family == IPv4);
         if (IN_MULTICAST(htonl(reply.addr.ip.v4)))
            type = "multicast";
      }
      xasprintf(name, "(%s)", type);
   }
   else  /* Correctly resolved name.  */
      *name = xstrdup(reply.name);

   dns_unqueue(&reply.addr);
   return (1);

error:
   warn("dns_get_result: ignoring read error");
   /* FIXME: re-align to stream?  restart dns child? */
   return (0);
}

void
dns_poll(void)
{
   struct addr ip;
   char *name;

   if (pid == -1)
      return; /* no child was started - we're not doing any DNS */

   while (dns_get_result(&ip, &name)) {
      /* push into hosts_db */
      struct bucket *b = host_find(&ip);

      if (b == NULL) {
         verbosef("resolved %s to %s but it's not in the DB!",
            addr_to_str(&ip), name);
         return;
      }
      if (b->u.host.dns != NULL) {
         verbosef("resolved %s to %s but it's already in the DB!",
            addr_to_str(&ip), name);
         return;
      }
      b->u.host.dns = name;
   }
}

/* ------------------------------------------------------------------------ */

struct qitem {
   STAILQ_ENTRY(qitem) entries;
   struct addr ip;
};

static STAILQ_HEAD(qhead, qitem) queue = STAILQ_HEAD_INITIALIZER(queue);

static void
enqueue(const struct addr *const ip)
{
   struct qitem *i;

   i = xmalloc(sizeof(*i));
   memcpy(&i->ip, ip, sizeof(i->ip));
   STAILQ_INSERT_TAIL(&queue, i, entries);
   verbosef("DNS: enqueued %s", addr_to_str(ip));
}

/* Return non-zero and populate <ip> pointer if queue isn't empty. */
static int
dequeue(struct addr *ip)
{
   struct qitem *i;

   i = STAILQ_FIRST(&queue);
   if (i == NULL)
      return (0);
   STAILQ_REMOVE_HEAD(&queue, entries);
   memcpy(ip, &i->ip, sizeof(*ip));
   free(i);
   verbosef("DNS: dequeued %s", addr_to_str(ip));
   return 1;
}

static void
xwrite(const int d, const void *buf, const size_t nbytes)
{
   ssize_t ret = write(d, buf, nbytes);

   if (ret == -1)
      err(1, "write");
   if (ret != (ssize_t)nbytes)
      err(1, "wrote %d bytes instead of all %d bytes", (int)ret, (int)nbytes);
}

static void
dns_main(void)
{
   struct addr ip;

   setproctitle("DNS child");
   fd_set_nonblock(dns_sock[CHILD]);
   verbosef("DNS child entering main DNS loop");
   for (;;) {
      int blocking;

      if (STAILQ_EMPTY(&queue)) {
         blocking = 1;
         fd_set_block(dns_sock[CHILD]);
         verbosef("entering blocking read loop");
      } else {
         blocking = 0;
         fd_set_nonblock(dns_sock[CHILD]);
         verbosef("non-blocking poll");
      }
      for (;;) {
         /* While we have input to process... */
         ssize_t numread = read(dns_sock[CHILD], &ip, sizeof(ip));
         if (numread == 0)
            exit(0); /* end of file, nothing more to do here. */
         if (numread == -1) {
            if (!blocking && (errno == EAGAIN))
               break; /* ran out of input */
            /* else error */
            err(1, "DNS: read failed");
         }
         if (numread != sizeof(ip))
            err(1, "DNS: read got %zu bytes, expecting %zu",
               numread, sizeof(ip));
         enqueue(&ip);
         if (blocking) {
            /* After one blocking read, become non-blocking so that when we
             * run out of input we fall through to queue processing.
             */
            blocking = 0;
            fd_set_nonblock(dns_sock[CHILD]);
         }
      }

      /* Process queue. */
      if (dequeue(&ip)) {
         struct dns_reply reply;
         struct sockaddr_in sin;
         struct sockaddr_in6 sin6;
         struct hostent *he;
         char host[NI_MAXHOST];
         int ret, flags;

         reply.addr = ip;
         flags = NI_NAMEREQD;
#  ifdef NI_IDN
         flags |= NI_IDN;
#  endif
         switch (ip.family) {
            case IPv4:
               sin.sin_family = AF_INET;
               sin.sin_addr.s_addr = ip.ip.v4;
               ret = getnameinfo((struct sockaddr *) &sin, sizeof(sin),
                                 host, sizeof(host), NULL, 0, flags);
               if (ret == EAI_FAMILY) {
                  verbosef("getnameinfo error %s, trying gethostbyname",
                     gai_strerror(ret));
                  he = gethostbyaddr(&sin.sin_addr.s_addr,
                     sizeof(sin.sin_addr.s_addr), sin.sin_family);
                  if (he == NULL) {
                     ret = EAI_FAIL;
                     verbosef("gethostbyname error %s", hstrerror(h_errno));
                  } else {
                     ret = 0;
                     strlcpy(host, he->h_name, sizeof(host));
                  }
               }
               break;
            case IPv6:
               sin6.sin6_family = AF_INET6;
               memcpy(&sin6.sin6_addr, &ip.ip.v6, sizeof(sin6.sin6_addr));
               ret = getnameinfo((struct sockaddr *) &sin6, sizeof(sin6),
                                 host, sizeof(host), NULL, 0, flags);
               break;
            default:
               errx(1, "unexpected ip.family = %d", ip.family);
         }

         if (ret != 0) {
            reply.name[0] = '\0';
            reply.error = ret;
         } else {
            assert(sizeof(reply.name) > sizeof(char *)); /* not just a ptr */
            strlcpy(reply.name, host, sizeof(reply.name));
            reply.error = 0;
         }
         fd_set_block(dns_sock[CHILD]);
         xwrite(dns_sock[CHILD], &reply, sizeof(reply));
         verbosef("DNS: %s is \"%s\".", addr_to_str(&reply.addr),
            (ret == 0) ? reply.name : gai_strerror(ret));
      }
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
