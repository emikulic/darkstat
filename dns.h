/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * dns.h: synchronous DNS in a child process.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

struct addr;

void dns_init(const char *privdrop_user);
void dns_stop(void);
void dns_queue(const struct addr *const ipaddr);
void dns_poll(void);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
