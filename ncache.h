/* darkstat 3
 * copyright (c) 2001-2006 Emil Mikulic.
 *
 * ncache.h: cache of protocol and service names.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

void ncache_init(void);
void ncache_free(void);
const char *getproto(const int proto);
const char *getservtcp(const int port);
const char *getservudp(const int port);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
