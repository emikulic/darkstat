/* darkstat 3
 * copyright (c) 2001-2006 Emil Mikulic.
 *
 * now.h: a cache of the current time
 * This lets us avoid superfluous gettimeofday() syscalls.
 */
#include <time.h>

extern time_t now; /* updated in the event loop in darkstat.c */
