/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
 *
 * acct.h: traffic accounting
 */

#include <stdint.h>

struct pktsummary;

extern uint64_t total_packets, total_bytes;

void acct_init_localnet(const char *spec);
void acct_for(const struct pktsummary * const sm);

extern unsigned int highest_port;

/* vim:set ts=3 sw=3 tw=78 expandtab: */
