/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
 *
 * err.c: BSD-like err() and warn() functions
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
#include "err.h"
#include "opt.h"
#include "pidfile.h"
#include "bsd.h" /* for strlcpy */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static void to_syslog(const char *type, const int want_err,
          const char *format, va_list va) _printflike_(3, 0);

static void
to_syslog(const char *type, const int want_err,
          const char *format, va_list va)
{
   char buf[512];
   size_t pos = 0;
   int saved_errno = errno;

   if (type != NULL) {
      strlcpy(buf, type, sizeof(buf));
      pos = strlen(buf);
   }
   vsnprintf(buf+pos, sizeof(buf)-pos, format, va);
   if (want_err) {
      strlcat(buf, ": ", sizeof(buf));
      strlcat(buf, strerror(saved_errno), sizeof(buf));
   }
   syslog(LOG_DEBUG, "%s", buf);
}

void
err(const int code, const char *format, ...)
{
   va_list va;

   va_start(va, format);
   if (opt_want_syslog)
      to_syslog("ERROR: ", 1, format, va);
   else {
      fprintf(stderr, "%5d: error: ", (int)getpid());
      vfprintf(stderr, format, va);
      fprintf(stderr, ": %s\n", strerror(errno));
   }
   va_end(va);
   pidfile_unlink();
   exit(code);
}

void
errx(const int code, const char *format, ...)
{
   va_list va;

   va_start(va, format);
   if (opt_want_syslog)
      to_syslog("ERROR: ", 0, format, va);
   else {
      fprintf(stderr, "%5d: error: ", (int)getpid());
      vfprintf(stderr, format, va);
      fprintf(stderr, "\n");
   }
   va_end(va);
   pidfile_unlink();
   exit(code);
}

void
warn(const char *format, ...)
{
   va_list va;

   va_start(va, format);
   if (opt_want_syslog)
      to_syslog("WARNING: ", 1, format, va);
   else {
      fprintf(stderr, "%5d: warning: ", (int)getpid());
      vfprintf(stderr, format, va);
      fprintf(stderr, ": %s\n", strerror(errno));
   }
   va_end(va);
}

void
warnx(const char *format, ...)
{
   va_list va;

   va_start(va, format);
   if (opt_want_syslog)
      to_syslog("WARNING: ", 0, format, va);
   else {
      fprintf(stderr, "%5d: warning: ", (int)getpid());
      vfprintf(stderr, format, va);
      fprintf(stderr, "\n");
   }
   va_end(va);
}

/* We interlock verbosef() between processes by using a pipe with a single
 * byte in it.  This pipe must be initialized before the first fork() in order
 * to work.  Then, verbosef() will block on a read() until it is able to
 * retrieve the byte.  After doing its business, it will put a byte back into
 * the pipe.
 *
 * This is completely silly and largely unnecessary.
 */
static int inited = 0;
static int lockpipe[2];

static void unlock(void);

static void
initlock(void)
{
   if (pipe(lockpipe) == -1)
      err(1, "pipe(lockpipe)");
   inited = 1;
   unlock();
}

static void
lock(void)
{
   char buf[1];

   if (!inited) initlock();
   if (read(lockpipe[0], buf, 1) != 1) {
      fprintf(stderr, "lock failed!\n");
      pidfile_unlink();
      exit(1);
   }
}

static void
unlock(void)
{
   char c = 0;

   if (write(lockpipe[1], &c, 1) != 1) {
      fprintf(stderr, "unlock failed!\n");
      pidfile_unlink();
      exit(1);
   }
}

void
verbosef(const char *format, ...)
{
   va_list va;

   if (!opt_want_verbose) return;
   va_start(va, format);
   if (opt_want_syslog)
      to_syslog(NULL, 0, format, va);
   else {
      lock();
      fprintf(stderr, "darkstat (%05d): ", (int)getpid());
      vfprintf(stderr, format, va);
      fprintf(stderr, "\n");
      unlock();
   }
   va_end(va);
}

void
dverbosef(const char *format _unused_, ...)
{
   /* disabled / do-nothing verbosef */
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
