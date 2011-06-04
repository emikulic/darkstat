/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * cap.h: interface to libpcap.
 */

#include <sys/types.h> /* OpenBSD needs this before select */
#include <sys/time.h> /* FreeBSD 4 needs this for struct timeval */
#include <sys/select.h>

extern unsigned int cap_pkts_recv, cap_pkts_drop;

void cap_init(const char *device, const char *filter, int promisc);
void cap_fd_set(fd_set *read_set, int *max_fd,
   struct timeval *timeout, int *need_timeout);
void cap_poll(fd_set *read_set);
void cap_stop(void);

void cap_from_file(const char *capfile, const char *filter);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
