/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
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

#include <sys/types.h>
#include <stdarg.h>

/* Note: the contents are 8-bit clean and not zero terminated! */

struct str;

struct str *str_make(void);
void str_free(struct str *s);
void str_extract(struct str *buf, size_t *len, char **str);
void str_appendn(struct str *buf, const char *s, const size_t len);
void str_appendstr(struct str *buf, const struct str *s);

#ifdef __GNUC__
/* amusing efficiency hack */
#include <string.h>
#define str_append(buf, s) str_appendn(buf, s, \
    (__builtin_constant_p(s) ? sizeof(s)-1 : strlen(s)) )
#else
void str_append(struct str *buf, const char *s);
#endif

size_t xvasprintf(char **result, const char *format, va_list va);
size_t xasprintf(char **result, const char *format, ...);
void str_appendf(struct str *buf, const char *format, ...);

struct str *length_of_time(const time_t t);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
