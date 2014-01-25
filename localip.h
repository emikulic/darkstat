/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * localip.h: determine the local IPs of an interface
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */
#ifndef __DARKSTAT_LOCALIP_H
#define __DARKSTAT_LOCALIP_H

#include <time.h>

struct local_ips {
   int is_valid;
   time_t last_update_mono;
   int num_addrs;
   struct addr *addrs;
};

void localip_init(struct local_ips *ips);
void localip_free(struct local_ips *ips);

void localip_update(const char *iface, struct local_ips *ips);
int is_localip(const struct addr * const a,
               const struct local_ips * const ips);

#endif
/* vim:set ts=3 sw=3 tw=80 et: */
