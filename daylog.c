/* darkstat 3
 * copyright (c) 2007 Emil Mikulic.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "darkstat.h"
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

static int
daylog_open(void)
{
   return open(daylog_fn, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0600);
}

static void
daylog_emit(void)
{
   int fd = daylog_open();

   if (fd != -1) {
      struct str *buf = str_make();
      char *s;
      size_t len;
      str_appendf(buf, "%s|%u|%qu|%qu|%qu|%qu\n",
         fmt_date(today_time), (unsigned int)today_time,
         bytes_in, bytes_out, pkts_in, pkts_out);
      str_extract(buf, &len, &s);

      (void)write(fd, s, len); /* ignore write errors */
      close(fd);
      free(s);
   }
}

void
daylog_init(const char *filename)
{
   int fd;
   struct str *buf;
   char *s;
   size_t len;

   daylog_fn = filename;
   today_time = time(NULL);
   tomorrow_time = tomorrow(today_time);
   verbosef("today is %u, tomorrow is %u",
      (unsigned int)today_time, (unsigned int)tomorrow_time);
   bytes_in = bytes_out = pkts_in = pkts_out = 0;

   fd = daylog_open();
   if (fd == -1)
      err(1, "couldn't open(\"%s\") for append", filename);

   buf = str_make();
   str_appendf(buf, "# logging started at %s (%u)\n",
      fmt_date(today_time), (unsigned int)today_time);
   str_extract(buf, &len, &s);
   (void)write(fd, s, len); /* ignore write errors */
   close(fd);
   free(s);
}

void daylog_free(void)
{
   int fd;
   struct str *buf;
   char *s;
   size_t len;

   today_time = time(NULL);

   /* Emit what's currently accumulated. */
   daylog_emit();

   fd = daylog_open();
   if (fd == -1) return;

   buf = str_make();
   str_appendf(buf, "# logging stopped at %s (%u)\n",
      fmt_date(today_time), (unsigned int)today_time);
   str_extract(buf, &len, &s);
   (void)write(fd, s, len); /* ignore write errors */
   close(fd);
   free(s);
}

void
daylog_acct(uint64_t amount, enum graph_dir dir)
{
   if (daylog_fn == NULL) return; /* disabled */

   /* Check if we need to rotate. */
   if (now >= tomorrow_time) {
      daylog_emit();

      today_time = now;
      tomorrow_time = tomorrow(today_time);
      bytes_in = bytes_out = pkts_in = pkts_out = 0;
      verbosef("rotated daylog, tomorrow = %u",
         (unsigned int)tomorrow_time);
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
