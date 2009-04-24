/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
 *
 * dns.c: synchronous DNS in a child process.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "darkstat.h"
#include "conv.h"
#include "decode.h"
#include "dns.h"
#include "err.h"
#include "hosts_db.h"
#include "queue.h"
#include "tree.h"

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

static void dns_main(void); /* this is what the child process runs */

#define CHILD 0 /* child process uses this socket */
#define PARENT 1
static int sock[2];
static pid_t pid = -1;

struct dns_reply {
   in_addr_t ip;
   int error; /* h_errno, or 0 if no error */
   char name[MAXHOSTNAMELEN];
};

void
dns_init(const char *privdrop_user)
{
   if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock) == -1)
      err(1, "socketpair");

   pid = fork();
   if (pid == -1)
      err(1, "fork");

   if (pid == 0) {
      /* We are the child. */
      privdrop(NULL /* don't chroot */, privdrop_user);
      close(sock[PARENT]);
      sock[PARENT] = -1;
      daemonize_finish(); /* drop our copy of the lifeline! */
      if (signal(SIGUSR1, SIG_IGN) == SIG_ERR)
         errx(1, "signal(SIGUSR1, ignore) failed");
      dns_main();
      verbosef("fell out of dns_main()");
      exit(0);
   } else {
      /* We are the parent. */
      close(sock[CHILD]);
      sock[CHILD] = -1;
      fd_set_nonblock(sock[PARENT]);
      verbosef("DNS child has PID %d", pid);
   }
}

void
dns_stop(void)
{
   if (pid == -1)
      return; /* no child was started */
   close(sock[PARENT]);
   if (kill(pid, SIGINT) == -1)
      err(1, "kill");
   verbosef("dns_stop() waiting for child");
   if (waitpid(pid, NULL, 0) == -1)
      err(1, "waitpid");
   verbosef("dns_stop() done waiting for child");
}

struct tree_rec {
   RB_ENTRY(tree_rec) ptree;
   in_addr_t ip;
};

static int
tree_cmp(struct tree_rec *a, struct tree_rec *b)
{
   if (a->ip < b->ip) return (-1); else
   if (a->ip > b->ip) return (+1); else
   return (0);
}

static RB_HEAD(tree_t, tree_rec) ip_tree = RB_INITIALIZER(&tree_rec);
/* Quiet warnings. */
static struct tree_rec * tree_t_RB_NEXT(struct tree_rec *elm)
   _unused_;
static struct tree_rec * tree_t_RB_MINMAX(struct tree_t *head, int val)
   _unused_;
RB_GENERATE(tree_t, tree_rec, ptree, tree_cmp)

void
dns_queue(const in_addr_t ip)
{
   struct tree_rec *rec;
   ssize_t num_w;

   if (pid == -1)
      return; /* no child was started - we're not doing any DNS */

   rec = xmalloc(sizeof(*rec));
   rec->ip = ip;
   if (RB_INSERT(tree_t, &ip_tree, rec) != NULL) {
      /* Already queued - this happens seldom enough that we don't care about
       * the performance hit of needlessly malloc()ing. */
      verbosef("already queued %s", ip_to_str(ip));
      free(rec);
      return;
   }

   num_w = write(sock[PARENT], &ip, sizeof(ip)); /* won't block */
   if (num_w == 0)
      warnx("dns_queue: write: ignoring end of file");
   else if (num_w == -1)
      warn("dns_queue: ignoring write error");
   else if (num_w != sizeof(ip))
      err(1, "dns_queue: wrote %d instead of %d",
         (int)num_w, (int)sizeof(ip));
}

static void
dns_unqueue(const in_addr_t ip)
{
   struct tree_rec tmp, *rec;

   tmp.ip = ip;
   if ((rec = RB_FIND(tree_t, &ip_tree, &tmp)) != NULL) {
      RB_REMOVE(tree_t, &ip_tree, rec);
      free(rec);
   }
   else
      verbosef("couldn't unqueue %s - not in queue!", ip_to_str(ip));
}

/*
 * Returns non-zero if result waiting, stores IP and name into given pointers
 * (name buffer is allocated by dns_poll)
 */
static int
dns_get_result(in_addr_t *ip, char **name)
{
   struct dns_reply reply;
   ssize_t numread;

   numread = read(sock[PARENT], &reply, sizeof(reply));
   if (numread == -1) {
      if (errno == EAGAIN)
         return (0); /* no input waiting */
      else
         goto error;
   }
   if (numread == 0)
      goto error; /* EOF */
   if (numread != sizeof(reply))
      errx(1, "dns_get_result read got %d, expected %d",
         (int)numread, (int)sizeof(reply));

   /* Return successful reply. */
   *ip = reply.ip;
   if (reply.error != 0)
      xasprintf(name, "(%s)", hstrerror(reply.error));
   else
      *name = xstrdup(reply.name);
   dns_unqueue(reply.ip);
   return (1);

error:
   warn("dns_get_result: ignoring read error");
   /* FIXME: re-align to stream?  restart dns child? */
   return (0);
}

void
dns_poll(void)
{
   in_addr_t ip;
   char *name;

   if (pid == -1)
      return; /* no child was started - we're not doing any DNS */

   while (dns_get_result(&ip, &name)) {
      /* push into hosts_db */
      struct bucket *b = host_find(ip);
      if (b == NULL) {
         verbosef("resolved %s to %s but it's not in the DB!",
            ip_to_str(ip), name);
         return;
      }
      if (b->u.host.dns != NULL) {
         verbosef("resolved %s to %s but it's already in the DB!",
            ip_to_str(ip), name);
         return;
      }
      b->u.host.dns = name;
   }
}

/* ------------------------------------------------------------------------ */

struct qitem {
   STAILQ_ENTRY(qitem) entries;
   in_addr_t ip;
};

STAILQ_HEAD(qhead, qitem) queue = STAILQ_HEAD_INITIALIZER(queue);

static void
enqueue(const in_addr_t ip)
{
   struct qitem *i;

   i = xmalloc(sizeof(*i));
   i->ip = ip;
   STAILQ_INSERT_TAIL(&queue, i, entries);
   verbosef("DNS: enqueued %s", ip_to_str(ip));
}

/* Return non-zero and populate <ip> pointer if queue isn't empty. */
static int
dequeue(in_addr_t *ip)
{
   struct qitem *i;

   i = STAILQ_FIRST(&queue);
   if (i == NULL)
      return (0);
   STAILQ_REMOVE_HEAD(&queue, entries);
   *ip = i->ip;
   free(i);
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
   in_addr_t ip;

#ifdef HAVE_SETPROCTITLE
   setproctitle("DNS child");
#endif
   fd_set_nonblock(sock[CHILD]);
   verbosef("DNS child entering main DNS loop");
   for (;;) {
      int blocking;

      if (STAILQ_EMPTY(&queue)) {
         blocking = 1;
         fd_set_block(sock[CHILD]);
         verbosef("entering blocking read loop");
      } else {
         blocking = 0;
         fd_set_nonblock(sock[CHILD]);
         verbosef("non-blocking poll");
      }
      for (;;) {
         /* While we have input to process... */
         ssize_t numread = read(sock[CHILD], &ip, sizeof(ip));
         if (numread == 0)
            exit(0); /* end of file, nothing more to do here. */
         if (numread == -1) {
            if (!blocking && (errno == EAGAIN))
               break; /* ran out of input */
            /* else error */
            err(1, "DNS: read failed");
         }
         if (numread != sizeof(ip))
            err(1, "DNS: read got %d bytes, expecting %d",
               (int)numread, (int)sizeof(ip));
         enqueue(ip);
         if (blocking) {
            /* After one blocking read, become non-blocking so that when we
             * run out of input we fall through to queue processing.
             */
            blocking = 0;
            fd_set_nonblock(sock[CHILD]);
         }
      }

      /* Process queue. */
      if (dequeue(&ip)) {
         struct dns_reply reply;
         struct hostent *he;

         reply.ip = ip;
         he = gethostbyaddr((char *)&ip, sizeof(ip), AF_INET);

         /* On some platforms (for example Linux with GLIBC 2.3.3), h_errno
          * will be non-zero here even though the lookup succeeded.
          */
         if (he == NULL) {
            reply.name[0] = '\0';
            reply.error = h_errno;
         } else {
            assert(sizeof(reply.name) > sizeof(char *)); /* not just a ptr */
            strlcpy(reply.name, he->h_name, sizeof(reply.name));
            reply.error = 0;
         }
         fd_set_block(sock[CHILD]);
         xwrite(sock[CHILD], &reply, sizeof(reply));
         verbosef("DNS: %s is %s", ip_to_str(ip),
            (h_errno == 0)?reply.name:hstrerror(h_errno));
      }
   }
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
