/* darkstat 3
 * copyright (c) 2001-2008 Emil Mikulic.
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

#include "darkstat.h"
#include "err.h"
#include "pidfile.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unistd.h>

void
err(const int code, const char *format, ...)
{
   va_list va;

   fprintf(stderr, "%5d: error: ", (int)getpid());
   va_start(va, format);
   vfprintf(stderr, format, va);
   va_end(va);
   fprintf(stderr, ": %s\n", strerror(errno));
   pidfile_unlink();
   exit(code);
}

void
errx(const int code, const char *format, ...)
{
   va_list va;

   fprintf(stderr, "%5d: error: ", (int)getpid());
   va_start(va, format);
   vfprintf(stderr, format, va);
   va_end(va);
   fprintf(stderr, "\n");
   pidfile_unlink();
   exit(code);
}

void
warn(const char *format, ...)
{
   va_list va;

   fprintf(stderr, "%5d: warning: ", (int)getpid());
   va_start(va, format);
   vfprintf(stderr, format, va);
   va_end(va);
   fprintf(stderr, ": %s\n", strerror(errno));
}

void
warnx(const char *format, ...)
{
   va_list va;

   fprintf(stderr, "%5d: warning: ", (int)getpid());
   va_start(va, format);
   vfprintf(stderr, format, va);
   va_end(va);
   fprintf(stderr, "\n");
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

int want_verbose = 0;

void
verbosef(const char *format, ...)
{
   va_list va;

   if (!want_verbose) return;
   lock();
   fprintf(stderr, "darkstat (%05d): ", (int)getpid());
   va_start(va, format);
   vfprintf(stderr, format, va);
   va_end(va);
   fprintf(stderr, "\n");
   unlock();
}

void
dverbosef(const char *format _unused_, ...)
{
   /* disabled / do-nothing verbosef */
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
