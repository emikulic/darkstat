/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * bsd.h: *BSD compatibility.
 */

#include <sys/types.h>

#include "config.h"

#ifndef HAVE_REAL_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_REAL_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_REAL_SETPROCTITLE
#ifdef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...);
#else
#define setproctitle(fmt, ...)
#endif
#endif

/* vim:set ts=3 sw=3 tw=78 expandtab: */
