/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * now.h: a cache of the current time.
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

void now_init(void);
void now_update(void); /* once per event loop (in darkstat.c) */

time_t now_real(void);
time_t now_mono(void);

/* Monotonic times can be negative (a time from before the machine booted) so
 * treat them as signed. */
time_t mono_to_real(const int64_t t);
int64_t real_to_mono(const time_t t);

/* Emits warnings if a call is too slow. */
struct timespec;
void timer_start(struct timespec *t);
void timer_stop(const struct timespec * const t,
                const int64_t nsec,
                const char *warning);

/* vim:set ts=3 sw=3 tw=80 et: */
