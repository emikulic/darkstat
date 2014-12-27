/* darkstat 3
 * copyright (c) 2001-2014 Emil Mikulic.
 *
 * conv.c: convenience functions.
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

#include "conv.h"

#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include "err.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PATH_DEVNULL "/dev/null"

/* malloc() that exits on failure. */
void *
xmalloc(const size_t size)
{
   void *ptr = malloc(size);

   if (ptr == NULL)
      errx(1, "malloc(): out of memory");
   return (ptr);
}

/* calloc() that exits on failure. */
void *
xcalloc(const size_t num, const size_t size)
{
   void *ptr = calloc(num, size);

   if (ptr == NULL)
      errx(1, "calloc(): out of memory");
   return (ptr);
}

/* realloc() that exits on failure. */
void *
xrealloc(void *original, const size_t size)
{
    void *ptr = realloc(original, size);

    if (ptr == NULL)
      errx(1, "realloc(): out of memory");
    return (ptr);
}

/* strdup() that exits on failure. */
char *
xstrdup(const char *s)
{
   char *tmp = strdup(s);

   if (tmp == NULL)
      errx(1, "strdup(): out of memory");
   return (tmp);
}

/* ---------------------------------------------------------------------------
 * Split string out of src with range [left:right-1]
 */
char *
split_string(const char *src, const size_t left, const size_t right)
{
    char *dest;
    assert(left <= right);
    assert(left < strlen(src));   /* [left means must be smaller */
    assert(right <= strlen(src)); /* right) means can be equal or smaller */

    dest = xmalloc(right - left + 1);
    memcpy(dest, src+left, right-left);
    dest[right-left] = '\0';
    return (dest);
}

/* ---------------------------------------------------------------------------
 * Uppercasify all characters in a string of given length.
 */
void
strntoupper(char *str, const size_t length)
{
    size_t i;

    for (i=0; i<length; i++)
        str[i] = toupper(str[i]);
}

/* ---------------------------------------------------------------------------
 * Returns non-zero if haystack starts with needle.
 */
int
str_starts_with(const char *haystack, const char *needle)
{
   int i = 0;

   while (needle[i] != '\0') {
      if ((haystack[i] == '\0') || (haystack[i] != needle[i]))
         return (0);
      i++;
   }
   return (1);
}

/* split - splits a string by a delimiter character into an array of
 * string chunks.
 *
 * The chunks and the array are dynamically allocated using xmalloc() so
 * it will errx() if it runs out of memory.
 *
 *    int num_chunks;
 *    char **chunks = split('.', "..one...two....", &num_chunks);
 *
 *    num_chunks = 2, chunks = { "one", "two", NULL }
 */
char **
split(const char delimiter, const char *str, unsigned int *num_chunks)
{
   unsigned int num = 0;
   char **chunks = NULL;
   size_t left, right = 0;

   #define PUSH(c) do { num++;  chunks = (char**) xrealloc(chunks, \
      sizeof(*chunks) * num);  chunks[num-1] = c; } while(0)

   for(;;) {
      /* find first non-delimiter */
      for (left = right; str[left] == delimiter; left++)
            ;

      if (str[left] == '\0')
         break; /* ran out of string */

      /* find first delimiter or end of string */
      for (right=left+1;
         str[right] != delimiter && str[right] != '\0';
         right++)
            ;

      /* split chunk out */
      PUSH( split_string(str, left, right) );

      if (str[right] == '\0')
         break; /* ran out of string */
      else
         right++;
   }

   /* return */
   PUSH(NULL);
   if (num_chunks != NULL)
      *num_chunks = num-1; /* NULL doesn't count */
   return (chunks);
   #undef PUSH
}

/* Given an HTTP query string and a key to search for, return the value
 * associated with it, or NULL if there is no such key or qs is NULL.
 * The returned string needs to be freed.
 *
 * e.g.:
 * qs = "sort=in&start=20";
 * qs_get(sq, "sort") returns "in"
 * qs_get(sq, "end") returns NULL
 */
char *
qs_get(const char *qs, const char *key)
{
   size_t pos, qslen, keylen;

   if (qs == NULL) return NULL;

   qslen = strlen(qs);
   keylen = strlen(key);
   pos = 0;
   while (pos < qslen) {
      if (!(pos + keylen + 1 < qslen))
         /* not enough room for "key" + "=" */
         return NULL;
      else {
         if (str_starts_with(qs+pos, key) && qs[pos+keylen] == '=') {
            /* found key= */
            size_t start, end;

            start = pos + keylen + 1;
            for (end=start; end<qslen && qs[end] != '&'; end++)
               ;
            return split_string(qs, start, end);
         } else {
            /* didn't find key, skip to next & */
            do { pos++; } while ((pos < qslen) && (qs[pos] != '&'));
            pos++; /* skip the ampersand */
         }
      }
   }
   return NULL; /* not found */
}

static int lifeline[2] = { -1, -1 };
static int fd_null = -1;

void
daemonize_start(void)
{
   pid_t f, w;

   if (pipe(lifeline) == -1)
      err(1, "pipe(lifeline)");

   fd_null = open(PATH_DEVNULL, O_RDWR, 0);
   if (fd_null == -1)
      err(1, "open(" PATH_DEVNULL ")");

   f = fork();
   if (f == -1)
      err(1, "fork");
   else if (f != 0) {
      /* parent: wait for child */
      char tmp[1];
      int status;

      verbosef("parent waiting");
      if (close(lifeline[1]) == -1)
         warn("close lifeline in parent");
      if (read(lifeline[0], tmp, sizeof(tmp)) != 0) /* expecting EOF */
         err(1, "lifeline read() failed");
      verbosef("parent done reading, calling waitpid");
      w = waitpid(f, &status, WNOHANG);
      verbosef("waitpid ret %d, status is %d", w, status);
      if (w == -1)
         err(1, "waitpid");
      else if (w == 0)
         /* child is running happily */
         exit(EXIT_SUCCESS);
      else
         /* child init failed, pass on its exit status */
         exit(WEXITSTATUS(status));
   }
   /* else we are the child: continue initializing */
}

void
daemonize_finish(void)
{
   if (fd_null == -1)
      return; /* didn't daemonize_start(), i.e. we're not daemonizing */

   if (setsid() == -1)
      err(1, "setsid");
   if (close(lifeline[0]) == -1)
      warn("close read end of lifeline in child");
   if (close(lifeline[1]) == -1)
      warn("couldn't cut the lifeline");

   /* close all our std fds */
   if (dup2(fd_null, STDIN_FILENO) == -1)
      warn("dup2(stdin)");
   if (dup2(fd_null, STDOUT_FILENO) == -1)
      warn("dup2(stdout)");
   if (dup2(fd_null, STDERR_FILENO) == -1)
      warn("dup2(stderr)");
   if (fd_null > 2)
      close(fd_null);
}

/*
 * For security, chroot (optionally) and drop privileges.
 * Pass a NULL chroot_dir to disable chroot() behaviour.
 */
void privdrop(const char *chroot_dir, const char *privdrop_user) {
   struct passwd *pw;

   errno = 0;
   pw = getpwnam(privdrop_user);

   if (pw == NULL) {
      if (errno == 0)
         errx(1, "getpwnam(\"%s\") failed: no such user", privdrop_user);
      else
         err(1, "getpwnam(\"%s\") failed", privdrop_user);
   }
   if (chroot_dir == NULL) {
      verbosef("no --chroot dir specified, darkstat will not chroot()");
   } else {
      tzset(); /* read /etc/localtime before we chroot */
      if (chdir(chroot_dir) == -1)
         err(1, "chdir(\"%s\") failed", chroot_dir);
      if (chroot(chroot_dir) == -1)
         err(1, "chroot(\"%s\") failed", chroot_dir);
      verbosef("chrooted into: %s", chroot_dir);
   }
   {
      gid_t list[1];
      list[0] = pw->pw_gid;
      if (setgroups(1, list) == -1)
         err(1, "setgroups");
   }
   if (setgid(pw->pw_gid) == -1)
      err(1, "setgid");
   if (setuid(pw->pw_uid) == -1)
      err(1, "setuid");
   verbosef("set uid/gid to %d/%d", (int)pw->pw_uid, (int)pw->pw_gid);
}

/* Make the specified file descriptor non-blocking. */
void
fd_set_nonblock(const int fd)
{
   int flags;

   if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
      err(1, "fcntl(fd %d) to get flags", fd);
   flags |= O_NONBLOCK;
   if (fcntl(fd, F_SETFL, flags) == -1)
      err(1, "fcntl(fd %d) to set O_NONBLOCK", fd);
   assert( (fcntl(fd, F_GETFL, 0) & O_NONBLOCK ) == O_NONBLOCK );
}

/* Make the specified file descriptor blocking. */
void
fd_set_block(const int fd)
{
   int flags;

   if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
      err(1, "fcntl(fd %d) to get flags", fd);
   flags &= ~O_NONBLOCK;
   if (fcntl(fd, F_SETFL, flags) == -1)
      err(1, "fcntl(fd %d) to unset O_NONBLOCK", fd);
   assert( (fcntl(fd, F_GETFL, 0) & O_NONBLOCK ) == 0 );
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
