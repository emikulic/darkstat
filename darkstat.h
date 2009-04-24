/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
 *
 * darkstat.h: general macros
 */

/*
 * We only care about the following from config.h:
 * - PACKAGE_NAME
 * - PACKAGE_VERSION
 * - PACKAGE_STRING
 */
#include "config.h"

#ifdef __GNUC__
# define _unused_ __attribute__((__unused__))
# define _noreturn_ __attribute__((__noreturn__))
#else
# define _unused_
# define _noreturn_
#endif

#if __GNUC__ == 2
# define inline __inline__
#else
# ifdef __TenDRA__
#  define inline __inline
# endif
#endif

#ifndef max
# define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef min
# define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* vim:set ts=3 sw=3 tw=78 expandtab: */
