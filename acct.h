/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
 *
 * acct.h: traffic accounting
 */

#include <stdint.h>

struct pktsummary;
struct local_ips;

extern uint64_t acct_total_packets, acct_total_bytes;

void acct_init_localnet(const char *spec);
void acct_for(const struct pktsummary * const sm,
              const struct local_ips * const local_ips);

/* vim:set ts=3 sw=3 tw=80 expandtab: */
