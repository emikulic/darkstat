/* darkstat 3
 * copyright (c) 2012 Emil Mikulic.
 *
 * now.c: a cache of the current time.
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
#include "err.h"
#include "now.h"

#include <assert.h>
#include <string.h>
#include <time.h>

static struct timespec clock_real, clock_mono;
static int now_initialized = 0;

long now_real(void) {
   assert(now_initialized);
   return clock_real.tv_sec;
}

long now_mono(void) {
   assert(now_initialized);
   return clock_mono.tv_sec;
}

static int before(const struct timespec *a, const struct timespec *b) {
   if (a->tv_sec < b->tv_sec)
      return 1;
   if (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec)
      return 1;
   return 0;
}

static void clock_update(const clockid_t clk_id,
                         struct timespec *dest,
                         const char *name) {
   struct timespec t;

   clock_gettime(clk_id, &t);
   if (now_initialized && before(&t, dest)) {
      verbosef("%s clock went backwards from %ld.%09ld to %ld.%09ld",
               name,
               (long)dest->tv_sec,
               (long)dest->tv_nsec,
               (long)t.tv_sec,
               (long)t.tv_nsec);
   }
   memcpy(dest, &t, sizeof(t));
}

static void all_clocks_update(void) {
   clock_update(CLOCK_REALTIME,  &clock_real, "realtime");
   clock_update(CLOCK_MONOTONIC, &clock_mono, "monotonic");
}

void now_init(void) {
   assert(!now_initialized);
   all_clocks_update();
   now_initialized = 1;
}

void now_update(void) {
   assert(now_initialized);
   all_clocks_update();
}

long mono_to_real(const long t) {
   assert(now_initialized);
   return t - clock_mono.tv_sec + clock_real.tv_sec;
}

long real_to_mono(const long t) {
   assert(now_initialized);
   return t - clock_real.tv_sec + clock_mono.tv_sec;
}

/* vim:set ts=3 sw=3 tw=80 et: */
