/* darkstat 3
 * copyright (c) 2007-2014 Emil Mikulic.
 *
 * pidfile.h: pidfile manglement
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
#include "str.h"
#include "pidfile.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

static int pidfd = -1;
static const char *pidname = NULL;

void pidfile_create(const char *chroot_dir,
                    const char *filename,
                    const char *privdrop_user) {
   struct passwd *pw;

   if (pidfd != -1)
      errx(1, "pidfile already created");

   errno = 0;
   pw = getpwnam(privdrop_user);

   if (pw == NULL) {
      if (errno == 0)
         errx(1, "getpwnam(\"%s\") failed: no such user", privdrop_user);
      else
         err(1, "getpwnam(\"%s\") failed", privdrop_user);
   }

   if (chroot_dir != NULL) {
      if (chdir(chroot_dir) == -1) {
         err(1, "chdir(\"%s\") failed", chroot_dir);
      }
   }
   pidname = filename;
   pidfd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600);
   if (pidfd == -1)
      err(1, "couldn't not create pidfile");
   if (chown(filename, pw->pw_uid, pw->pw_gid) == -1)
      err(1, "couldn't chown pidfile");
}

void
pidfile_write_close(void)
{
   struct str *s;
   size_t len;
   char *buf;

   if (pidfd == -1)
      errx(1, "cannot write pidfile: not created");

   s = str_make();
   str_appendf(s, "%u\n", (unsigned int)getpid());
   str_extract(s, &len, &buf);

   if (write(pidfd, buf, len) != (int)len)
      err(1, "couldn't write to pidfile");
   free(buf);
   if (close(pidfd) == -1)
      warn("problem closing pidfile");
}

void
pidfile_unlink(void)
{
   if (pidname == NULL)
      return; /* pidfile wasn't created */
   if (unlink(pidname) == -1)
      warn("problem unlinking pidfile");
}

/* vim:set ts=3 sw=3 tw=78 et: */
