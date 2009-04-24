/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
 *
 * acct.h: traffic accounting
 */

#include "decode.h"

extern uint64_t total_packets, total_bytes;

void acct_init_localnet(const char *spec);
void acct_for(const pktsummary *sm);

extern unsigned int highest_port;

/* vim:set ts=3 sw=3 tw=78 expandtab: */
