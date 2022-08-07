/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * str.h: string buffer with pool-based reallocation
 *
 * Permission to use, copy, modify, and distribute this file for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef __DARKSTAT_STR_H
#define __DARKSTAT_STR_H

#include "cdefs.h"

#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>  /* for uint64_t */

typedef long long   signed int qd;   /* as in appendf("%qd") */
typedef long long unsigned int qu;   /* as in appendf("%qu") */
typedef long long unsigned int lld;  /* as in printf("%lld") */
typedef long long unsigned int llu;  /* as in printf("%llu") */

_Static_assert(sizeof(qd) == sizeof(int64_t), "qd must be int64_t sized");
_Static_assert(sizeof(qu) == sizeof(uint64_t), "qu must be uint64_t sized");
_Static_assert(sizeof(lld) == sizeof(int64_t), "lld must be int64_t sized");
_Static_assert(sizeof(llu) == sizeof(uint64_t), "llu must be uint64_t sized");

/* Note: the contents are 8-bit clean and not zero terminated! */

struct str;

struct str *str_make(void);
void str_free(struct str *s);
void str_extract(struct str *buf, size_t *len, char **str);
void str_appendn(struct str *buf, const char *s, const size_t len);
void str_appendstr(struct str *buf, const struct str *s);

#ifdef __GNUC__
/* amusing efficiency hack */
# include <string.h>
# define str_append(buf, s) \
   str_appendn(buf, s, \
               (__builtin_constant_p(s) ? sizeof(s)-1 : strlen(s)) )
#else
void str_append(struct str *buf, const char *s);
#endif

size_t xvasprintf(char **result, const char *format, va_list va)
   _printflike_(2, 0);
size_t xasprintf(char **result, const char *format, ...) _printflike_(2, 3);
void str_vappendf(struct str *s, const char *format, va_list va)
   _printflike_(2, 0);
void str_appendf(struct str *s, const char *format, ...) _printflike_(2, 3);

struct str *length_of_time(const time_t t);
ssize_t str_write(const struct str * const buf, const int fd);
size_t str_len(const struct str * const buf);

void str_printf_at(struct str *s, size_t pos, const char *format, ...);

#endif  /* __DARKSTAT_STR_H */
/* vim:set ts=3 sw=3 tw=78 expandtab: */
