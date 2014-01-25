/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * err.h: BSD-like err() and warn() functions
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

#include "cdefs.h"

void err(const int code, const char *format, ...)
   _noreturn_ _printflike_(2, 3);
void errx(const int code, const char *format, ...)
   _noreturn_ _printflike_(2, 3);

void warn(const char *format, ...) _printflike_(1, 2);
void warnx(const char *format, ...) _printflike_(1, 2);

void verbosef(const char *format, ...) _printflike_(1, 2);
void dverbosef(const char *format _unused_, ...) _printflike_(1, 2);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
