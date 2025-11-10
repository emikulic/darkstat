/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * pf.h: interface to OpenBSD pf.
 */

#include <sys/types.h> /* OpenBSD needs this before select */
#include <sys/time.h> /* FreeBSD 4 needs this for struct timeval */
#include <sys/select.h>

void pfsync_start(void);
void pfsync_fd_set(fd_set *read_set, int *max_fd,
   struct timeval *timeout, int *need_timeout);
int pfsync_poll(void);
void pfsync_stop(void);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
