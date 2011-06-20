/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * conv.h: convenience functions.
 */

#include <sys/types.h>

void *xmalloc(const size_t size);
void *xcalloc(const size_t num, const size_t size);
void *xrealloc(void *original, const size_t size);
char *xstrdup(const char *s);
char *split_string(const char *src, const size_t left, const size_t right);
void  strntoupper(char *str, const size_t length);
int   str_starts_with(const char *haystack, const char *needle);
char**split(const char delimiter, const char *str, unsigned int *num_chunks);
char *qs_get(const char *qs, const char *key);

void  daemonize_start(void);
void  daemonize_finish(void);
void  privdrop(const char *chroot_dir, const char *privdrop_user);
void  fd_set_nonblock(const int fd);
void  fd_set_block(const int fd);

/* vim:set ts=3 sw=3 tw=78 expandtab: */
