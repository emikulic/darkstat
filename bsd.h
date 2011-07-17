/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * bsd.h: *BSD compatibility.
 */

#include <sys/types.h>

#include "config.h"

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_SETPROCTITLE
#define setproctitle(fmt, ...) /* no-op */
#endif

/* vim:set ts=3 sw=3 tw=78 expandtab: */
