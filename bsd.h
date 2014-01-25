/* darkstat 3
 * copyright (c) 2011-2014 Emil Mikulic.
 *
 * bsd.h: *BSD compatibility.
 */

#include <sys/types.h>
#include "config.h"
#ifdef HAVE_BSD_STRING_H
# include <bsd/string.h>
#endif
#ifdef HAVE_BSD_UNISTD_H
# include <bsd/unistd.h>
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_SETPROCTITLE
#define setproctitle(fmt) /* no-op */
#endif

/* vim:set ts=3 sw=3 tw=78 expandtab: */
