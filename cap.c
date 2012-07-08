/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * cap.c: interface to libpcap.
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
#include "opt.h"

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

/* The cap process life-cycle:
 *
 * Init           - cap_init()
 * Fill fd_set    - cap_fd_set()
 * Poll           - cap_poll()
 * Stop           - cap_stop()
 */

/* Globals - only useful within this module. */
static pcap_t *pcap = NULL;
static int pcap_fd = -1;
static const struct linkhdr *linkhdr = NULL;

#define CAP_TIMEOUT 500 /* granularity of capture buffer, in milliseconds */

/* ---------------------------------------------------------------------------
 * Init pcap.  Exits on failure.
 */
void
cap_init(const char *device, const char *filter, int promisc)
{
   char errbuf[PCAP_ERRBUF_SIZE], *tmp_device;
   int linktype, snaplen, waited;

   /* pcap doesn't like device being const */
   tmp_device = xstrdup(device);

   /* Open packet capture descriptor. */
   waited = 0;
   for (;;) {
      errbuf[0] = '\0'; /* zero length string */
      pcap = pcap_open_live(
         tmp_device,
         1,          /* snaplen, irrelevant at this point */
         0,          /* promisc, also irrelevant */
         CAP_TIMEOUT,
         errbuf);
      if (pcap != NULL) break; /* success! */

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
   linktype = pcap_datalink(pcap);
   verbosef("linktype is %d", linktype);
   if ((linktype == DLT_EN10MB) && opt_want_macs)
      hosts_db_show_macs = 1;
   linkhdr = getlinkhdr(linktype);
   if (linkhdr == NULL)
      errx(1, "unknown linktype %d", linktype);
   if (linkhdr->decoder == NULL)
      errx(1, "no decoder for linktype %d", linktype);
   snaplen = getsnaplen(linkhdr);
   if (opt_want_pppoe) {
      snaplen += PPPOE_HDR_LEN;
      if (linktype != DLT_EN10MB)
         errx(1, "can't do PPPoE decoding on a non-Ethernet linktype");
   }
   verbosef("calculated snaplen minimum %d", snaplen);
#ifdef linux
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
   pcap_close(pcap);
   errbuf[0] = '\0'; /* zero length string */
   pcap = pcap_open_live(
      tmp_device,
      snaplen,
      promisc,
      CAP_TIMEOUT,
      errbuf);

   if (pcap == NULL)
      errx(1, "pcap_open_live(): %s", errbuf);

   if (errbuf[0] != '\0') /* not zero length anymore -> warning */
      warnx("pcap_open_live() warning: %s", errbuf);

   free(tmp_device);

   if (promisc)
      verbosef("capturing in promiscuous mode");
   else
      verbosef("capturing in non-promiscuous mode");

   /* Set filter expression, if any. */
   if (filter != NULL)
   {
      struct bpf_program prog;
      char *tmp_filter = xstrdup(filter);
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

   pcap_fd = pcap_fileno(pcap);

   /* set non-blocking */
#ifdef linux
   if (pcap_setnonblock(pcap, 1, errbuf) == -1)
      errx(1, "pcap_setnonblock(): %s", errbuf);
#else
{ int one = 1;
   if (ioctl(pcap_fd, FIONBIO, &one) == -1)
      err(1, "ioctl(pcap_fd, FIONBIO)"); }
#endif

#ifdef BIOCSETWF
{
   /* Deny all writes to the socket */
   struct bpf_insn bpf_wfilter[] = { BPF_STMT(BPF_RET+BPF_K, 0) };
   int wf_len = sizeof(bpf_wfilter) / sizeof(struct bpf_insn);
   struct bpf_program pr;

   pr.bf_len = wf_len;
   pr.bf_insns = bpf_wfilter;

   if (ioctl(pcap_fd, BIOCSETWF, &pr) == -1)
      err(1, "ioctl(pcap_fd, BIOCSETFW)");
   verbosef("filtered out BPF writes");
}
#endif

#ifdef BIOCLOCK
   /* set "locked" flag (no reset) */
   if (ioctl(pcap_fd, BIOCLOCK) == -1)
      err(1, "ioctl(pcap_fd, BIOCLOCK)");
   verbosef("locked down BPF for security");
#endif
}

/*
 * Set pcap_fd in the given fd_set.
 */
void
cap_fd_set(
#ifdef linux
   fd_set *read_set _unused_,
   int *max_fd _unused_,
   struct timeval *timeout,
#else
   fd_set *read_set,
   int *max_fd,
   struct timeval *timeout _unused_,
#endif
   int *need_timeout)
{
   assert(*need_timeout == 0); /* we're first to get a shot at this */
#ifdef linux
   /*
    * Linux's BPF is immediate, so don't select() as it will lead to horrible
    * performance.  Instead, use a timeout for buffering.
    */
   *need_timeout = 1;
   timeout->tv_sec = 0;
   timeout->tv_usec = CAP_TIMEOUT * 1000; /* msec->usec */
#else
   /* We have a BSD-like BPF, we can select() on it. */
   FD_SET(pcap_fd, read_set);
   *max_fd = MAX(*max_fd, pcap_fd);
#endif
}

unsigned int cap_pkts_recv = 0, cap_pkts_drop = 0;

static void
cap_stats_update(void)
{
   struct pcap_stat ps;

   if (pcap_stats(pcap, &ps) != 0) {
      warnx("pcap_stats(): %s", pcap_geterr(pcap));
      return;
   }

   cap_pkts_recv = ps.ps_recv;
   cap_pkts_drop = ps.ps_drop;
}

/*
 * Print hexdump of received packet.
 */
static void
hexdump(const u_char *buf, const uint32_t len)
{
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
 * in linkhdr struct.
 */
static void callback(u_char *user _unused_,
                     const struct pcap_pkthdr *pheader,
                     const u_char *pdata) {
   struct pktsummary sm;

   if (opt_want_hexdump)
      hexdump(pdata, pheader->caplen);
   memset(&sm, 0, sizeof(sm));
   if (linkhdr->decoder(pheader, pdata, &sm))
      acct_for(&sm);
}

/*
 * Process any packets currently in the capture buffer.
 */
void
cap_poll(fd_set *read_set
#ifdef linux
   _unused_
#endif
)
{
   int total, ret;

#ifndef linux /* We don't use select() on Linux. */
   if (!FD_ISSET(pcap_fd, read_set)) {
      verbosef("cap_poll premature");
      return;
   }
#endif

   /* Once per capture poll, check our IP address.  It's used in accounting
    * for traffic graphs.
    */
   localip_update(opt_interface, local_ips);

   total = 0;
   for (;;) {
#ifndef NDEBUG
      struct timeval t1;
      gettimeofday(&t1, NULL);
#endif
      ret = pcap_dispatch(
            pcap,
            -1,               /* count, -1 = entire buffer */
            callback,
            NULL);            /* user */

      if (ret < 0) {
         warnx("pcap_dispatch(): %s", pcap_geterr(pcap));
         return;
      }

#ifndef NDEBUG
      {
         struct timeval t2;
         int td;

         gettimeofday(&t2, NULL);
         td = (t2.tv_sec - t1.tv_sec) * 1000000 + t2.tv_usec - t1.tv_usec;
         if (td > CAP_TIMEOUT*1000)
            warnx("pcap_dispatch blocked for %d usec! (expected <= %d usec)\n",
               td, CAP_TIMEOUT*1000);
      }
#endif

      /* Despite count = -1, Linux will only dispatch one packet at a time. */
      total += ret;

#ifdef linux
      /* keep looping until we've dispatched all the outstanding packets */
      if (ret == 0) break;
#else
      /* we get them all on the first shot */
      break;
#endif
   }
   cap_stats_update();
}

void
cap_stop(void)
{
   pcap_close(pcap);
}

/* Run through entire capfile. */
void
cap_from_file(const char *capfile, const char *filter)
{
   char errbuf[PCAP_ERRBUF_SIZE];
   int linktype, ret;

   /* Open packet capture descriptor. */
   errbuf[0] = '\0'; /* zero length string */
   pcap = pcap_open_offline(capfile, errbuf);

   if (pcap == NULL)
      errx(1, "pcap_open_offline(): %s", errbuf);

   if (errbuf[0] != '\0') /* not zero length anymore -> warning */
      warnx("pcap_open_offline() warning: %s", errbuf);

   /* Work out the linktype. */
   linktype = pcap_datalink(pcap);
   linkhdr = getlinkhdr(linktype);
   if (linkhdr == NULL)
      errx(1, "unknown linktype %d", linktype);
   if (linkhdr->decoder == NULL)
      errx(1, "no decoder for linktype %d", linktype);
   if (linktype == DLT_EN10MB) /* FIXME: impossible with capfile? */
      hosts_db_show_macs = 1;

   /* Set filter expression, if any. */ /* FIXME: factor! */
   if (filter != NULL)
   {
      struct bpf_program prog;
      char *tmp_filter = xstrdup(filter);
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

   /* Process file. */
   ret = pcap_dispatch(
         pcap,
         -1,               /* count, -1 = entire buffer */
         callback,
         NULL);            /* user */

   if (ret < 0)
      errx(1, "pcap_dispatch(): %s", pcap_geterr(pcap));
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
