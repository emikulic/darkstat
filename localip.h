/* darkstat 3
 * copyright (c) 2001-2006 Emil Mikulic.
 *
 * localip.h: determine local IP of our capture interface
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include <netinet/in.h> /* for in_addr_t */

extern in_addr_t localip;
extern struct in6_addr localip6;

void localip_init(const char *interface);
void localip_update(void);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
