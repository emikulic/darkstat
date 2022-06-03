/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * pf.c: read pf states, and hand them off to decode and acct.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#ifdef __OpenBSD__

#include "pf.h"
#include "acct.h"
#include "cdefs.h"
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
#include "cache.h"

#include <sys/ioctl.h>
#include <net/pfvar.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define MIN_NUM_STATES 1024
#define NUM_STATE_INC  1024

#define DEFAULT_CACHE_SIZE 10000

struct pfsync_state *state_buf = NULL;
size_t state_buf_len = 0;
size_t num_states = 0;

int pf_dev = -1;

struct local_ips local_ips;

void pfsync_start(void) {
   struct str *ifs = str_make();
   str_appendn(ifs, "", 1); /* NUL terminate */
   {
      size_t _;
      str_extract(ifs, &_, &title_interfaces);
   }

	pf_dev = open("/dev/pf", O_RDONLY);
	if (pf_dev == -1) {
      errx(1, "pfsync_start");
   }

   if (cache_init(1<<16)) {
      errx(1, "pfsync_start: cache_init");
   }

   // FIXME: initialize ip addresses based on egress, by default?
   localip_init(&local_ips);
}

void pfsync_fd_set(fd_set *read_set, int *max_fd,
   struct timeval *timeout, int *need_timeout) {
   assert(*need_timeout == 0); /* we're first to get a shot at the fd_set */

   *need_timeout = 1;
   timeout->tv_sec = 0;
   timeout->tv_usec = 1000;
}

void
alloc_buf(size_t ns)
{
	size_t len;

	if (ns < MIN_NUM_STATES)
		ns = MIN_NUM_STATES;

	len = ns;

	if (len >= state_buf_len) {
		len += NUM_STATE_INC;
		state_buf = reallocarray(state_buf, len,
		    sizeof(struct pfsync_state));
		if (state_buf == NULL)
			errx(1, "realloc");
		state_buf_len = len;
	}
}

void pfsync_handle_state(struct pfsync_state * s, struct sc_ent * ent) {
   int afto, dir;

#undef v4

   // FIXME: support ipv6
   if (s->key[0].af != AF_INET || s->key[1].af != AF_INET) {
      return;
   }

   u_int64_t bytes_delta[2];
   u_int64_t packets_delta[2];
   if (ent != NULL) {
      bytes_delta[0] = ent->bytes_delta[0];
      bytes_delta[1] = ent->bytes_delta[1];
      packets_delta[0] = ent->packets_delta[0];
      packets_delta[1] = ent->packets_delta[1];
   } else {
      bytes_delta[0] = COUNTER(s->bytes[0]);
      bytes_delta[1] = COUNTER(s->bytes[1]);
      packets_delta[0] = COUNTER(s->packets[0]);
      packets_delta[1] = COUNTER(s->packets[1]);
   }

   afto = s->key[PF_SK_STACK].af == s->key[PF_SK_WIRE].af ? 0 : 1;
   dir = afto ? PF_OUT : s->direction;

   struct pktsummary sm;
   memset(&sm, 0, sizeof(sm));

   sm.src.family = IPv4;
   sm.dst.family = IPv4;
   sm.proto = s->proto;

   sm.len = (dir == PF_OUT) ? bytes_delta[0] : bytes_delta[1];
   sm.packets = (dir == PF_OUT) ? packets_delta[0] : packets_delta[1];

   if (sm.len > 0) {
      struct pfsync_state_key *ks = &s->key[afto ? PF_SK_STACK : PF_SK_WIRE];
      sm.src.ip.v4 = ks->addr[1].pfa.v4.s_addr;
      sm.src_port = ntohs(ks->port[1]);

      sm.dst.ip.v4 = ks->addr[0].pfa.v4.s_addr;
      sm.dst_port = ntohs(ks->port[0]);

      acct_for(&sm, &local_ips);
   }

   sm.len = (dir == PF_OUT) ? bytes_delta[1] : bytes_delta[0];
   sm.packets = (dir == PF_OUT) ? packets_delta[1] : packets_delta[0];
   if (sm.len > 0) {
      struct pfsync_state_key *ks = &s->key[PF_SK_STACK];
      sm.src.ip.v4 = ks->addr[0].pfa.v4.s_addr;
      sm.src_port = ntohs(ks->port[0]);

      sm.dst.ip.v4 = ks->addr[1].pfa.v4.s_addr;
      sm.dst_port = ntohs(ks->port[1]);

      acct_for(&sm, &local_ips);
   }
}

int pfsync_poll(void) {
   int n;
	struct pfioc_states ps;

   ps.ps_len = 0;
   ps.ps_states = NULL;

   if (ioctl(pf_dev, DIOCGETSTATES, &ps) == -1) {
      errx(1, "DIOCGETSTATES");
   }

	for (;;) {
		size_t sbytes = state_buf_len * sizeof(struct pfsync_state);

		ps.ps_len = sbytes;
		ps.ps_states = state_buf;

		if (ioctl(pf_dev, DIOCGETSTATES, &ps) == -1) {
			errx(1, "DIOCGETSTATES");
		}
		num_states = ps.ps_len / sizeof(struct pfsync_state);

		if (ps.ps_len < sbytes)
			break;

		alloc_buf(num_states);
	}

   for (n = 0; n < num_states; n++) {
      struct sc_ent *ent = cache_state(state_buf + n);
      if (ent != NULL) {
         pfsync_handle_state(state_buf + n, ent);
      }
   }
   cache_endupdate();

   return 1;
}

void pfsync_stop(void) {
   int ret = close(pf_dev);
   if (ret == -1) {
      errx(1, "pfsync_stop: close");
   }

   localip_free(&local_ips);
}

#endif

/* vim:set ts=3 sw=3 tw=78 expandtab: */
