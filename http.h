/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * http.h: embedded webserver.
 */

#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>

void http_init_base(const char *url);
void http_add_bindaddr(const char *bindaddr);
void http_listen(const unsigned short bindport);
void http_fd_set(fd_set *recv_set, fd_set *send_set, int *max_fd,
   struct timeval *timeout, int *need_timeout);
void http_poll(fd_set *read_set, fd_set *write_set);
void http_stop(void);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
