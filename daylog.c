/* darkstat 3
 * copyright (c) 2007-2014 Emil Mikulic.
 *
 * daylog.c: daily usage log
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#define _GNU_SOURCE 1 /* for O_NOFOLLOW on Linux */

#include "cdefs.h"
#include "err.h"
#include "daylog.h"
#include "str.h"
#include "now.h"

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char *daylog_fn = NULL;
static time_t today_real, tomorrow_real;
static uint64_t bytes_in, bytes_out, pkts_in, pkts_out;

#define DAYLOG_DATE_LEN 26 /* strlen("1900-01-01 00:00:00 +1234") + 1 */
static char datebuf[DAYLOG_DATE_LEN];

static char *fmt_date(time_t when) {
    if (strftime(datebuf,
                 DAYLOG_DATE_LEN,
                 "%Y-%m-%d %H:%M:%S %z",
                 localtime(&when)) == 0)
            errx(1, "strftime() failed in fmt_date()");
    return datebuf;
}

/* Given some time today, find the first second of tomorrow. */
static time_t tomorrow(time_t t_before) {
   time_t t_after;
   struct tm tm, *lt;

   lt = localtime(&t_before);
   memcpy(&tm, lt, sizeof(tm));
   tm.tm_sec = 0;
   tm.tm_min = 0;
   tm.tm_hour = 0;
   tm.tm_mday = lt->tm_mday + 1; /* tomorrow */
   t_after = mktime(&tm);
   assert(t_after > t_before);
   return t_after;
}

/* Warns on error. */
static void daylog_write(const char *format, ...) _printflike_(1, 2);
static void daylog_write(const char *format, ...) {
   int fd;
   ssize_t wr;
   va_list va;
   struct str *buf;

   assert(daylog_fn != NULL);
   fd = open(daylog_fn, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0600);
   if (fd == -1) {
      warn("daylog_write: couldn't open '%s' for append", daylog_fn);
      return;
   }

   buf = str_make();
   va_start(va, format);
   str_vappendf(buf, format, va);
   va_end(va);

   wr = str_write(buf, fd);
   if (wr == -1)
      warn("daylog_write: couldn't write to '%s'", daylog_fn);
   else if (wr != (ssize_t)str_len(buf))
      warnx("daylog_write: truncated write to '%s': wrote %d of %d bytes",
           daylog_fn,
           (int)wr,
           (int)str_len(buf));
   close(fd);
   str_free(buf);
}

static void daylog_emit(void) {
   daylog_write("%s|%qu|%qu|%qu|%qu|%qu\n",
                fmt_date(today_real),
                (qu)today_real,
                (qu)bytes_in,
                (qu)bytes_out,
                (qu)pkts_in,
                (qu)pkts_out);
}

void daylog_init(const char *filename) {
   daylog_fn = filename;
   today_real = now_real();
   tomorrow_real = tomorrow(today_real);
   verbosef("today is %llu, tomorrow is %llu",
            (llu)today_real,
            (llu)tomorrow_real);
   bytes_in = bytes_out = pkts_in = pkts_out = 0;

   daylog_write("# logging started at %s (%qu)\n",
                fmt_date(today_real), (qu)today_real);
}

void daylog_free(void) {
   today_real = now_real();
   daylog_emit(); /* Emit what's currently accumulated before we exit. */
   daylog_write("# logging stopped at %s (%qu)\n",
                fmt_date(today_real), (qu)today_real);
}

void daylog_acct(uint64_t amount, enum graph_dir dir) {
   if (daylog_fn == NULL)
      return; /* daylogging disabled */

   /* Check if we need to update the log. */
   if (now_real() >= tomorrow_real) {
      daylog_emit();

      today_real = now_real();
      tomorrow_real = tomorrow(today_real);
      bytes_in = bytes_out = pkts_in = pkts_out = 0;
      verbosef("updated daylog, tomorrow = %llu", (llu)tomorrow_real);
   }

   /* Accounting. */
   if (dir == GRAPH_IN) {
      bytes_in += amount;
      pkts_in++;
   } else {
      assert(dir == GRAPH_OUT);
      bytes_out += amount;
      pkts_out++;
   }
}

/* vim:set ts=3 sw=3 tw=78 et: */
