/* darkstat 3
 * copyright (c) 2001-2009 Emil Mikulic.
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

void err(const int code, const char *format, ...) _noreturn_;
void errx(const int code, const char *format, ...) _noreturn_;

void warn(const char *format, ...);
void warnx(const char *format, ...);

extern int want_verbose, want_syslog;
void verbosef(const char *format, ...);
void dverbosef(const char *format _unused_, ...);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
