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
#include "opt.h"

#ifdef __GNUC__
# define _unused_ __attribute__((__unused__))
# define _noreturn_ __attribute__((__noreturn__))
# define _printflike_(fmtarg, firstvararg) \
   __attribute__((__format__ (__printf__, fmtarg, firstvararg) ))
#else
# define _unused_
# define _noreturn_
# define _printflike_(fmtarg, firstvararg)
#endif

#if __GNUC__ == 2
# define inline __inline__
#else
# ifdef __TenDRA__
#  define inline __inline
# endif
#endif

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901
#define restrict __restrict
#endif

#ifndef max
# define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef min
# define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* vim:set ts=3 sw=3 tw=78 expandtab: */
