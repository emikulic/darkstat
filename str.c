/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
 *
 * str.c: string buffer with pool-based reallocation
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

#include "conv.h"
#include "err.h"
#include "str.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> /* for uint32_t on Linux and OS X */
#include <unistd.h>

#define INITIAL_LEN 1024

struct str {
   char *buf;
   size_t len, pool;
};

struct str *
str_make(void)
{
   struct str *s = xmalloc(sizeof(*s));
   s->len = 0;
   s->pool = INITIAL_LEN;
   s->buf = xmalloc(s->pool);
   return (s);
}

void
str_free(struct str *s)
{
   free(s->buf);
   free(s);
}

/*
 * Extract struct str into buffer and length, freeing the struct in the
 * process.
 */
void
str_extract(struct str *s, size_t *len, char **str)
{
   *len = s->len;
   *str = s->buf;
   free(s);
}

void
str_appendn(struct str *buf, const char *s, const size_t len)
{
   if (buf->pool < buf->len + len) {
      /* pool has dried up */
      while (buf->pool < buf->len + len)
         buf->pool *= 2;
      buf->buf = xrealloc(buf->buf, buf->pool);
   }
   memcpy(buf->buf + buf->len, s, len);
   buf->len += len;
}

void
str_appendstr(struct str *buf, const struct str *s)
{
   str_appendn(buf, s->buf, s->len);
}

#ifndef str_append
void
str_append(struct str *buf, const char *s)
{
   str_appendn(buf, s, strlen(s));
}
#endif

/*
 * Apparently, some wacky locales use periods, or another character that isn't
 * a comma, to separate thousands.  If you are afflicted by such a locale,
 * change this macro:
 */
#define COMMA ','

/* 2^32 = 4,294,967,296 (10 digits, 13 chars) */
#define I32_MAXLEN 13

/* 2^64 = 18,446,744,073,709,551,616 (20 digits, 26 chars) */
#define I64_MAXLEN 26

static void
str_append_u32(struct str *s, const uint32_t i, const int mod_sep)
{
   char out[I32_MAXLEN];
   int pos;
   unsigned int len;
   uint32_t rem, next;

   if (i == 0) {
      str_append(s, "0");
      return;
   }

   pos = sizeof(out)-1;
   len = 0;
   rem = i;

   while (rem > 0) {
      assert(pos >= 0);
      next = rem / 10;
      rem = rem - next * 10;
      assert(rem < 10);
      out[pos] = '0' + rem;
      pos--;
      len++;
      rem = next;
      if (mod_sep && (rem > 0) && (len > 0) && (len % 3 == 0)) {
         out[pos] = COMMA;
         pos--;
      }
   }
   str_appendn(s, out+pos+1, sizeof(out)-1-pos);
}

static void
str_append_i32(struct str *s, int32_t i, const int mod_sep)
{
   if (i < 0) {
      str_append(s, "-");
      i = -i;
   }
   str_append_u32(s, (uint32_t)i, mod_sep);
}

static void
str_append_u64(struct str *s, const uint64_t i, const int mod_sep)
{
   char out[I64_MAXLEN];
   int pos;
   unsigned int len;
   uint64_t rem, next;
   uint32_t rem32, next32;

   if (i == 0) {
      str_append(s, "0");
      return;
   }

   pos = sizeof(out)-1;
   len = 0;
   rem = i;

   while (rem >= 4294967295U) {
      assert(pos >= 0);
      next = rem / 10;
      rem = rem - next * 10;
      assert(rem < 10);
      out[pos] = '0' + rem;
      pos--;
      len++;
      rem = next;
      if (mod_sep && (rem > 0) && (len > 0) && (len % 3 == 0)) {
         out[pos] = COMMA;
         pos--;
      }
   }

   /*
    * Stick to 32-bit math when we can as it's faster on 32-bit platforms.
    * FIXME: a tunable way to switch this off?
    */
   rem32 = (uint32_t)rem;
   while (rem32 > 0) {
      assert(pos >= 0);
      next32 = rem32 / 10;
      rem32 = rem32 - next32 * 10;
      assert(rem32 < 10);
      out[pos] = '0' + rem32;
      pos--;
      len++;
      rem32 = next32;
      if (mod_sep && (rem32 > 0) && (len > 0) && (len % 3 == 0)) {
         out[pos] = COMMA;
         pos--;
      }
   }
   str_appendn(s, out+pos+1, sizeof(out)-1-pos);
}

static void
str_append_i64(struct str *s, int64_t i, const int mod_sep)
{
   if (i < 0) {
      str_append(s, "-");
      i = -i;
   }
   str_append_u64(s, (uint64_t)i, mod_sep);
}

static void
str_append_hex8(struct str *s, const uint8_t b)
{
   char out[2];
   static const char hexset[] = "0123456789abcdef";

   out[0] = hexset[ ((b >> 4) & 15) ];
   out[1] = hexset[ (b & 15) ];
   str_appendn(s, out, 2);
}

/* accepted formats: %s %d %u %x
 * accepted modifiers: q and '
 *
 * %x is equivalent to %02x and expects a uint8_t
 */
void str_vappendf(struct str *s, const char *format, va_list va) {
   size_t pos, len;
   len = strlen(format);

   for (pos=0; pos<len; pos++) {
      size_t span_start = pos, span_len = 0;

      while ((format[pos] != '\0') && (format[pos] != '%')) {
         span_len++;
         pos++;
      }
      if (span_len > 0)
         str_appendn(s, format+span_start, span_len);

      if (format[pos] == '%') {
         int mod_quad = 0, mod_sep = 0;
         char *arg_str;
FORMAT:
         pos++;
         switch (format[pos]) {
         case '%':
            str_append(s, "%");
            break;
         case 'q':
            mod_quad = 1;
            goto FORMAT;
         case '\'':
            mod_sep = 1;
            goto FORMAT;
         case 's':
            arg_str = va_arg(va, char*);
            str_append(s, arg_str);
            /* str_append can be a macro!  passing it va_arg can result in
             * va_arg being called twice
             */
            break;
         case 'd':
            if (mod_quad)
               str_append_i64(s, va_arg(va, int64_t), mod_sep);
            else
               str_append_i32(s, (int32_t)va_arg(va, int), mod_sep);
            break;
         case 'u':
            if (mod_quad)
               str_append_u64(s, va_arg(va, uint64_t), mod_sep);
            else
               str_append_u32(s, (uint32_t)va_arg(va, unsigned int), mod_sep);
            break;
         case 'x':
            str_append_hex8(s, (uint8_t)va_arg(va, int));
            break;
         default:
            errx(1, "format string is \"%s\", unknown format '%c' at %u",
               format, format[pos], (unsigned int)pos);
         }
      }
   }
}

void
str_appendf(struct str *s, const char *format, ...)
{
   va_list va;
   va_start(va, format);
   str_vappendf(s, format, va);
   va_end(va);
}

size_t
xvasprintf(char **result, const char *format, va_list va)
{
   size_t len;
   struct str *s = str_make();
   str_vappendf(s, format, va);
   str_appendn(s, "", 1); /* "" still contains \0 */
   str_extract(s, &len, result);
   return (len-1);
}

size_t
xasprintf(char **result, const char *format, ...)
{
   va_list va;
   size_t ret;
   va_start(va, format);
   ret = xvasprintf(result, format, va);
   va_end(va);
   return (ret);
}

/*
 * Format a length of time in seconds to "n days, n hrs, n mins, n secs".
 * Returns a newly allocated str.
 */
struct str *
length_of_time(const time_t t)
{
   struct str *buf = str_make();
   int secs  =  t % 60;
   int mins  = (t / 60) % 60;
   int hours = (t / 3600) % 24;
   int days  =  t / 86400;

   int show_zeroes = 0;

   if (days > 0) {
      str_appendf(buf, "%d %s", days, (days==1)?"day":"days");
      show_zeroes = 1;
   }

   if (show_zeroes || (hours > 0)) {
      if (show_zeroes) str_append(buf, ", ");
      str_appendf(buf, "%d %s", hours, (hours==1)?"hr":"hrs");
      show_zeroes = 1;
   }

   if (show_zeroes || (mins > 0)) {
      if (show_zeroes) str_append(buf, ", ");
      str_appendf(buf, "%d %s", mins, (mins==1)?"min":"mins");
      show_zeroes = 1;
   }

   if (show_zeroes) str_append(buf, ", ");
   str_appendf(buf, "%d %s", secs, (secs==1)?"sec":"secs");

   return buf;
}

ssize_t str_write(const struct str * const buf, const int fd) {
   return write(fd, buf->buf, buf->len);
}

size_t str_len(const struct str * const buf) {
   return buf->len;
}

void
str_printf_at(struct str *s, size_t pos, const char *format, ...)
{
   size_t len = s->len;

   va_list va;
   va_start(va, format);
   if (pos < len) {
      s->len = pos;
      str_vappendf(s, format, va);
      if (len > s->len)
         s->len = len;
   }
   va_end(va);
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
