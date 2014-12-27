/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * cap.c: capture packets, and hand them off to decode and acct.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "acct.h"
#include "cdefs.h"
#include "cap.h"
#include "config.h"
#include "conv.h"
#include "decode.h"
#include "err.h"
#include "hosts_db.h"
#include "localip.h"
#include "now.h"
#include "opt.h"
#include "queue.h"
#include "str.h"

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h> /* Solaris' FIONBIO hides here */
#endif
#include <assert.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *title_interfaces = NULL; /* for html.c */

/* The cap process life-cycle:
 *  - cap_add_ifname() one or more times
 *  - cap_add_filter() zero or more times
 *  - cap_start() once to start listening
 * Once per main loop:
 *  - cap_fd_set() to update the select() set
 *  - cap_poll() to read from ready pcap fds
 * Shutdown:
 *  - cap_stop()
 */

struct strnode {
   STAILQ_ENTRY(strnode) entries;
   const char *str;
};

struct cap_iface {
   STAILQ_ENTRY(cap_iface) entries;

   const char *name;
   const char *filter;
   pcap_t *pcap;
   int fd;
   const struct linkhdr *linkhdr;
   struct local_ips local_ips;
};

static STAILQ_HEAD(cli_ifnames_head, strnode) cli_ifnames =
   STAILQ_HEAD_INITIALIZER(cli_ifnames);

static STAILQ_HEAD(cli_filters_head, strnode) cli_filters =
   STAILQ_HEAD_INITIALIZER(cli_filters);

static STAILQ_HEAD(cap_ifs_head, cap_iface) cap_ifs =
   STAILQ_HEAD_INITIALIZER(cap_ifs);

/* The read timeout passed to pcap_open_live() */
#define CAP_TIMEOUT_MSEC 500

void cap_add_ifname(const char *ifname) {
   struct strnode *n = xmalloc(sizeof(*n));
   n->str = ifname;
   STAILQ_INSERT_TAIL(&cli_ifnames, n, entries);
}

void cap_add_filter(const char *filter) {
   struct strnode *n = xmalloc(sizeof(*n));
   n->str = filter;
   STAILQ_INSERT_TAIL(&cli_filters, n, entries);
}

static void cap_set_filter(pcap_t *pcap, const char *filter) {
   struct bpf_program prog;
   char *tmp_filter;

   if (filter == NULL)
      return;

   tmp_filter = xstrdup(filter);
   if (pcap_compile(
         pcap,
         &prog,
         tmp_filter,
         1,          /* optimize */
         0)          /* netmask */
         == -1)
      errx(1, "pcap_compile(): %s", pcap_geterr(pcap));

   if (pcap_setfilter(pcap, &prog) == -1)
      errx(1, "pcap_setfilter(): %s", pcap_geterr(pcap));

   pcap_freecode(&prog);
   free(tmp_filter);
}

/* Start capturing on just one interface. Called from cap_start(). */
static void cap_start_one(struct cap_iface *iface, const int promisc) {
   char errbuf[PCAP_ERRBUF_SIZE], *tmp_device;
   int linktype, snaplen, waited;

   /* pcap wants a non-const interface name string */
   tmp_device = xstrdup(iface->name);
   if (iface->filter)
      verbosef("capturing on interface '%s' with filter '%s'",
         tmp_device, iface->filter);
   else
      verbosef("capturing on interface '%s' with no filter", tmp_device);

   /* Open packet capture descriptor. */
   waited = 0;
   for (;;) {
      errbuf[0] = '\0'; /* zero length string */
      iface->pcap = pcap_open_live(
         tmp_device,
         1,          /* snaplen, irrelevant at this point */
         0,          /* promisc, also irrelevant */
         CAP_TIMEOUT_MSEC,
         errbuf);
      if (iface->pcap != NULL)
         break; /* success! */

      if ((opt_wait_secs != -1) && strstr(errbuf, "device is not up")) {
         if ((opt_wait_secs > 0) && (waited >= opt_wait_secs))
            errx(1, "waited %d secs, giving up: pcap_open_live(): %s",
               waited, errbuf);

         verbosef("waited %d secs, interface is not up", waited);
         sleep(1);
         waited++;
      }
      else errx(1, "pcap_open_live(): %s", errbuf);
   }

   /* Work out the linktype and what snaplen we need. */
   linktype = pcap_datalink(iface->pcap);
   verbosef("linktype is %d", linktype);
   if ((linktype == DLT_EN10MB) && opt_want_macs)
      hosts_db_show_macs = 1;
   iface->linkhdr = getlinkhdr(linktype);
   if (iface->linkhdr == NULL)
      errx(1, "unknown linktype %d", linktype);
   if (iface->linkhdr->decoder == NULL)
      errx(1, "no decoder for linktype %d", linktype);
   snaplen = getsnaplen(iface->linkhdr);
   if (opt_want_pppoe) {
      snaplen += PPPOE_HDR_LEN;
      if (linktype != DLT_EN10MB)
         errx(1, "can't do PPPoE decoding on a non-Ethernet linktype");
   }
   verbosef("calculated snaplen minimum %d", snaplen);
#ifdef linux
   /* FIXME: actually due to libpcap moving to mmap (!!!)
    * work out which version and fix the way we do capture
    * on linux:
    */

   /* Ubuntu 9.04 has a problem where requesting snaplen <= 60 will
    * give us 42 bytes, and we need at least 54 for TCP headers.
    *
    * Hack to set minimum snaplen to tcpdump's default:
    */
   snaplen = MAX(snaplen, 96);
#endif
   if (opt_want_snaplen > -1)
      snaplen = opt_want_snaplen;
   verbosef("using snaplen %d", snaplen);

   /* Close and re-open pcap to use the new snaplen. */
   pcap_close(iface->pcap);
   errbuf[0] = '\0'; /* zero length string */
   iface->pcap = pcap_open_live(
      tmp_device,
      snaplen,
      promisc,
      CAP_TIMEOUT_MSEC,
      errbuf);

   if (iface->pcap == NULL)
      errx(1, "pcap_open_live(): %s", errbuf);

   if (errbuf[0] != '\0') /* not zero length anymore -> warning */
      warnx("pcap_open_live() warning: %s", errbuf);

   free(tmp_device);

   if (promisc)
      verbosef("capturing in promiscuous mode");
   else
      verbosef("capturing in non-promiscuous mode");

   cap_set_filter(iface->pcap, iface->filter);
   iface->fd = pcap_fileno(iface->pcap);

   /* set non-blocking */
#ifdef linux
   if (pcap_setnonblock(iface->pcap, 1, errbuf) == -1)
      errx(1, "pcap_setnonblock(): %s", errbuf);
#else
   {
      int one = 1;
      if (ioctl(iface->fd, FIONBIO, &one) == -1)
         err(1, "ioctl(iface->fd, FIONBIO)");
   }
#endif

#ifdef BIOCSETWF
   {
      /* Deny all writes to the socket */
      struct bpf_insn bpf_wfilter[] = { BPF_STMT(BPF_RET+BPF_K, 0) };
      int wf_len = sizeof(bpf_wfilter) / sizeof(struct bpf_insn);
      struct bpf_program pr;

      pr.bf_len = wf_len;
      pr.bf_insns = bpf_wfilter;

      if (ioctl(iface->fd, BIOCSETWF, &pr) == -1)
         err(1, "ioctl(iface->fd, BIOCSETFW)");
      verbosef("filtered out BPF writes");
   }
#endif

#ifdef BIOCLOCK
   /* set "locked" flag (no reset) */
   if (ioctl(iface->fd, BIOCLOCK) == -1)
      err(1, "ioctl(iface->fd, BIOCLOCK)");
   verbosef("locked down BPF for security");
#endif
}

void cap_start(const int promisc) {
   struct str *ifs = str_make();

   assert(STAILQ_EMPTY(&cap_ifs));
   if (STAILQ_EMPTY(&cli_ifnames))
      errx(1, "no interfaces specified");

   /* For each ifname */
   while (!STAILQ_EMPTY(&cli_ifnames)) {
      struct strnode *ifname, *filter = NULL;
      struct cap_iface *iface = xmalloc(sizeof(*iface));

      ifname = STAILQ_FIRST(&cli_ifnames);
      STAILQ_REMOVE_HEAD(&cli_ifnames, entries);

      if (!STAILQ_EMPTY(&cli_filters)) {
         filter = STAILQ_FIRST(&cli_filters);
         STAILQ_REMOVE_HEAD(&cli_filters, entries);
      }

      iface->name = ifname->str;
      iface->filter = (filter == NULL) ? NULL : filter->str;
      iface->pcap = NULL;
      iface->fd = -1;
      iface->linkhdr = NULL;
      localip_init(&iface->local_ips);
      STAILQ_INSERT_TAIL(&cap_ifs, iface, entries);
      cap_start_one(iface, promisc);

      free(ifname);
      if (filter) free(filter);

      if (str_len(ifs) == 0)
         str_append(ifs, iface->name);
      else
         str_appendf(ifs, ", %s", iface->name);
   }
   verbosef("all capture interfaces prepared");

   /* Deallocate extra filters, if any. */
   while (!STAILQ_EMPTY(&cli_filters)) {
      struct strnode *filter = STAILQ_FIRST(&cli_filters);

      verbosef("ignoring extraneous filter '%s'", filter->str);
      STAILQ_REMOVE_HEAD(&cli_filters, entries);
      free(filter);
   }

   str_appendn(ifs, "", 1); /* NUL terminate */
   {
      size_t _;
      str_extract(ifs, &_, &title_interfaces);
   }
}

#ifdef linux
# define _unused_on_linux_ _unused_
# define _unused_otherwise_
#else
# define _unused_on_linux_
# define _unused_otherwise_ _unused_
#endif

/*
 * Set pcap_fd in the given fd_set.
 */
void cap_fd_set(fd_set *read_set _unused_on_linux_,
                int *max_fd _unused_on_linux_,
                struct timeval *timeout _unused_otherwise_,
                int *need_timeout) {
   assert(*need_timeout == 0); /* we're first to get a shot at the fd_set */

#ifdef linux
   /*
    * Linux's BPF is immediate, so don't select() as it will lead to horrible
    * performance.  Instead, use a timeout for buffering.
    */
   *need_timeout = 1;
   timeout->tv_sec = 0;
   timeout->tv_usec = CAP_TIMEOUT_MSEC * 1000;
#else
   {
      struct cap_iface *iface;
      STAILQ_FOREACH(iface, &cap_ifs, entries) {
         /* We have a BSD-like BPF, we can select() on it. */
         FD_SET(iface->fd, read_set);
         *max_fd = MAX(*max_fd, iface->fd);
      }
   }
#endif
}

unsigned int cap_pkts_recv = 0, cap_pkts_drop = 0;

static void cap_stats_update(void) {
   struct cap_iface *iface;

   cap_pkts_recv = 0;
   cap_pkts_drop = 0;
   STAILQ_FOREACH(iface, &cap_ifs, entries) {
      struct pcap_stat ps;
      if (pcap_stats(iface->pcap, &ps) != 0) {
         warnx("pcap_stats('%s'): %s", iface->name, pcap_geterr(iface->pcap));
         return;
      }
      cap_pkts_recv += ps.ps_recv;
      cap_pkts_drop += ps.ps_drop;
   }
}

/* Print hexdump of received packet to stdout, for debugging. */
static void hexdump(const u_char *buf,
                    const uint32_t len,
                    const struct linkhdr *linkhdr) {
   uint32_t i, col;

   printf("packet of %u bytes:\n", len);
   for (i=0, col=0; i<len; i++) {
      if (col == 0) printf(" ");
      printf("%02x", buf[i]);
      if (i+1 == linkhdr->hdrlen)
         printf("|"); /* marks end of link headers (e.g. ethernet) */
      else
         printf(" ");
      col += 3;
      if (col >= 72) {
         printf("\n");
         col = 0;
      }
   }
   if (col != 0) printf("\n");
   printf("\n");
}

/* Callback function for pcap_dispatch() which chains to the decoder specified
 * in the linkhdr struct.
 */
static void callback(u_char *user,
                     const struct pcap_pkthdr *pheader,
                     const u_char *pdata) {
   const struct cap_iface * const iface = (struct cap_iface *)user;
   struct pktsummary sm;

   if (opt_want_hexdump)
      hexdump(pdata, pheader->caplen, iface->linkhdr);
   memset(&sm, 0, sizeof(sm));
   if (iface->linkhdr->decoder(pheader, pdata, &sm))
      acct_for(&sm, &iface->local_ips);
}

/* Process any packets currently in the capture buffer.
 * Returns 0 on error (usually means the interface went down).
 */
int cap_poll(fd_set *read_set _unused_on_linux_) {
   struct cap_iface *iface;
   static int told = 0;

   STAILQ_FOREACH(iface, &cap_ifs, entries) {
      /* Once per capture poll, check our IP address.  It's used in accounting
       * for traffic graphs.
       */
      localip_update(iface->name, &iface->local_ips);
      if (!told && iface->local_ips.num_addrs == 0) {
         verbosef("interface '%s' has no addresses, "
                  "your graphs will be blank",
                  iface->name);
         verbosef("please read the darkstat manpage, "
                  "and consider using the -l option");
         told = 1;
      }

      for (;;) {
         struct timespec t;
         int ret;

         timer_start(&t);
         ret = pcap_dispatch(
               iface->pcap,
               -1, /* count = entire buffer */
               callback,
               (u_char*)iface); /* user = struct to pass to callback */
         timer_stop(&t,
                    2 * CAP_TIMEOUT_MSEC * 1000000,
                    "pcap_dispatch took too long");

         if (ret < 0) {
            warnx("pcap_dispatch('%s'): %s",
               iface->name, pcap_geterr(iface->pcap));
            return 0;
         }

#if 0 /* debugging */
         verbosef("iface '%s' got %d pkts", iface->name, ret);
#endif

#ifdef linux
         /* keep looping until we've dispatched all the outstanding packets */
         if (ret == 0)
            break;
#else
         /* we get them all on the first shot */
         break;
#endif
      }
   }
   cap_stats_update();
   return 1;
}

void cap_stop(void) {
   while (!STAILQ_EMPTY(&cap_ifs)) {
      struct cap_iface *iface = STAILQ_FIRST(&cap_ifs);

      STAILQ_REMOVE_HEAD(&cap_ifs, entries);
      pcap_close(iface->pcap);
      localip_free(&iface->local_ips);
      free(iface);
   }
   free(title_interfaces);
   title_interfaces = NULL;
}

/* This is only needed by the DNS child. In the main process, the deallocation
 * happens in cap_start().
 */
void cap_free_args(void) {
   while (!STAILQ_EMPTY(&cli_ifnames)) {
      struct strnode *ifname = STAILQ_FIRST(&cli_ifnames);
      STAILQ_REMOVE_HEAD(&cli_ifnames, entries);
      free(ifname);
   }

   while (!STAILQ_EMPTY(&cli_filters)) {
      struct strnode *filter = STAILQ_FIRST(&cli_filters);
      STAILQ_REMOVE_HEAD(&cli_filters, entries);
      free(filter);
   }
}

/* Run through entire capfile. */
void cap_from_file(const char *capfile) {
   char errbuf[PCAP_ERRBUF_SIZE];
   int linktype, ret;
   struct cap_iface iface;

   iface.name = NULL;
   iface.filter = NULL;
   iface.pcap = NULL;
   iface.fd = -1;
   iface.linkhdr = NULL;
   localip_init(&iface.local_ips);

   /* Process cmdline filters. */
   if (!STAILQ_EMPTY(&cli_filters))
      iface.filter = STAILQ_FIRST(&cli_filters)->str;
   while (!STAILQ_EMPTY(&cli_filters)) {
      struct strnode *n = STAILQ_FIRST(&cli_filters);
      STAILQ_REMOVE_HEAD(&cli_filters, entries);
      free(n);
   }

   /* Open packet capture descriptor. */
   errbuf[0] = '\0'; /* zero length string */
   iface.pcap = pcap_open_offline(capfile, errbuf);

   if (iface.pcap == NULL)
      errx(1, "pcap_open_offline(): %s", errbuf);

   if (errbuf[0] != '\0') /* not zero length anymore -> warning */
      warnx("pcap_open_offline() warning: %s", errbuf);

   /* Work out the linktype. */
   linktype = pcap_datalink(iface.pcap);
   iface.linkhdr = getlinkhdr(linktype);
   if (iface.linkhdr == NULL)
      errx(1, "unknown linktype %d", linktype);
   if (iface.linkhdr->decoder == NULL)
      errx(1, "no decoder for linktype %d", linktype);

   cap_set_filter(iface.pcap, iface.filter);

   /* Process file. */
   ret = pcap_dispatch(
         iface.pcap,
         -1,               /* count, -1 = entire buffer */
         callback,
         (u_char*)&iface); /* user */

   if (ret < 0)
      errx(1, "pcap_dispatch(): %s", pcap_geterr(iface.pcap));

   localip_free(&iface.local_ips);
   pcap_close(iface.pcap);
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
