/* darkstat 3
 * copyright (c) 2007-2011 Emil Mikulic.
 *
 * daylog.c: daily usage log
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#define _GNU_SOURCE 1 /* for O_NOFOLLOW on Linux */

#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "err.h"
#include "daylog.h"
#include "str.h"
#include "now.h"

static const char *daylog_fn = NULL;
static time_t today_time, tomorrow_time;
static uint64_t bytes_in, bytes_out, pkts_in, pkts_out;

#define DAYLOG_DATE_LEN 26 /* strlen("1900-01-01 00:00:00 +1234") + 1 */
static char datebuf[DAYLOG_DATE_LEN];

static char *
fmt_date(const time_t when)
{
    time_t tmp = when;
    if (strftime(datebuf, DAYLOG_DATE_LEN,
        "%Y-%m-%d %H:%M:%S %z", localtime(&tmp) ) == 0)
            errx(1, "strftime() failed in fmt_date()");
    return (datebuf);
}

/* Given some time today, find the first second of tomorrow. */
static time_t
tomorrow(const time_t today)
{
   time_t tmp = today;
   struct tm tm, *lt;

   lt = localtime(&tmp);
   memcpy(&tm, lt, sizeof(tm));
   tm.tm_sec = 0;
   tm.tm_min = 0;
   tm.tm_hour = 0;
   tm.tm_mday = lt->tm_mday + 1; /* tomorrow */
   return mktime(&tm);
}

/* Warns on error. */
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
   daylog_write("%s|%u|%qu|%qu|%qu|%qu\n",
                fmt_date(today_time), (unsigned int)today_time,
                bytes_in, bytes_out, pkts_in, pkts_out);
}

void daylog_init(const char *filename) {
   daylog_fn = filename;
   today_time = time(NULL);
   tomorrow_time = tomorrow(today_time);
   verbosef("today is %u, tomorrow is %u",
      (unsigned int)today_time, (unsigned int)tomorrow_time);
   bytes_in = bytes_out = pkts_in = pkts_out = 0;

   daylog_write("# logging started at %s (%u)\n",
                fmt_date(today_time), (unsigned int)today_time);
}

void daylog_free(void) {
   today_time = time(NULL);
   daylog_emit(); /* Emit what's currently accumulated before we exit. */
   daylog_write("# logging stopped at %s (%u)\n",
                fmt_date(today_time), (unsigned int)today_time);
}

void daylog_acct(uint64_t amount, enum graph_dir dir) {
   if (daylog_fn == NULL) return; /* disabled */

   /* Check if we need to update the log. */
   if (now >= tomorrow_time) {
      daylog_emit();

      today_time = now;
      tomorrow_time = tomorrow(today_time);
      bytes_in = bytes_out = pkts_in = pkts_out = 0;
      verbosef("updated daylog, tomorrow = %u", (unsigned int)tomorrow_time);
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
