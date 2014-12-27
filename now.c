/* darkstat 3
 * copyright (c) 2012-2014 Emil Mikulic.
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
#include "str.h"

#include <assert.h>
#include <string.h>
#include <time.h>

#if defined(__MACH__) && !defined(__gnu_hurd__)
/* Fake up clock_gettime() on OS X. */
#  include <sys/time.h>
#  include <inttypes.h>
#  include <mach/mach.h>
#  include <mach/mach_time.h>

   typedef int clockid_t;
#  define CLOCK_REALTIME 0
#  define CLOCK_MONOTONIC 1

   static uint64_t mono_first = 0;

   int clock_gettime(clockid_t clk_id, struct timespec *tp) {
      if (clk_id == CLOCK_REALTIME) {
         struct timeval tv;
         gettimeofday(&tv, NULL);
         tp->tv_sec = tv.tv_sec;
         tp->tv_nsec = tv.tv_usec * 1000;
         return 0;
      }
      if (clk_id == CLOCK_MONOTONIC) {
         uint64_t t = mach_absolute_time();
         mach_timebase_info_data_t timebase;
         mach_timebase_info(&timebase);
         if (!mono_first) {
            mono_first = t;
         }
         uint64_t tdiff = (t - mono_first) * timebase.numer / timebase.denom;
         tp->tv_sec = tdiff / 1000000000;
         tp->tv_nsec = tdiff % 1000000000;
         return 0;
      }
      return -1;
   }
#endif  /* __MACH__ */

static struct timespec clock_real, clock_mono;
static int now_initialized = 0;

time_t now_real(void) {
   assert(now_initialized);
   return clock_real.tv_sec;
}

time_t now_mono(void) {
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

static void warn_backwards(const char *name,
                           const struct timespec * const t0,
                           const struct timespec * const t1) {
   verbosef("%s clock went backwards from %lld.%09lld to %lld.%09lld",
            name,
            (lld)t0->tv_sec,
            (lld)t0->tv_nsec,
            (lld)t1->tv_sec,
            (lld)t1->tv_nsec);
}

static void clock_update(const clockid_t clk_id,
                         struct timespec *dest,
                         const char *name) {
   struct timespec t;

   clock_gettime(clk_id, &t);
   if (now_initialized && before(&t, dest)) {
      warn_backwards(name, &t, dest);
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

time_t mono_to_real(const int64_t t) {
   assert(now_initialized);
   return (time_t)(t - (int64_t)clock_mono.tv_sec + (int64_t)clock_real.tv_sec);
}

int64_t real_to_mono(const time_t t) {
   assert(now_initialized);
   return (int64_t)(t - clock_real.tv_sec + clock_mono.tv_sec);
}

void timer_start(struct timespec *t) {
   clock_gettime(CLOCK_MONOTONIC, t);
}

static int64_t ts_diff(const struct timespec * const a,
                       const struct timespec * const b) {
   return (int64_t)(a->tv_sec - b->tv_sec) * 1000000000 +
          a->tv_nsec - b->tv_nsec;
}

void timer_stop(const struct timespec * const t0,
                const int64_t nsec,
                const char *warning) {
   struct timespec t1;
   int64_t diff;

   clock_gettime(CLOCK_MONOTONIC, &t1);
   if (before(&t1, t0)) {
      warn_backwards("monotonic timer", t0, &t1);
      return;
   }
   diff = ts_diff(&t1, t0);
   if (diff > nsec) {
      warnx("%s (took %lld nsec, over threshold of %lld nsec)",
            warning,
            (lld)diff,
            (lld)nsec);
   }
}

/* vim:set ts=3 sw=3 tw=80 et: */
