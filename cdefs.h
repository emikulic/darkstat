/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * cdefs.h: compiler-specific defines
 *
 * This file borrows from FreeBSD's sys/cdefs.h
 */

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

#ifndef MAX
# define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
# define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
# ifdef __COUNTER__
#  define _Static_assert(x, y)    __Static_assert(x, __COUNTER__)
# else
#  define _Static_assert(x, y)    __Static_assert(x, __LINE__)
# endif
# define __Static_assert(x, y)   ___Static_assert(x, y)
# define ___Static_assert(x, y)  typedef char __assert_ ## y[(x) ? 1 : -1]
#endif

/* vim:set ts=3 sw=3 tw=78 expandtab: */
