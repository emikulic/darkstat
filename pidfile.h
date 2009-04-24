/* darkstat 3
 * copyright (c) 2007 Emil Mikulic.
 *
 * pidfile.h: pidfile manglement
 */

void pidfile_create(const char *chroot_dir, const char *filename,
   const char *privdrop_user);
void pidfile_write_close(void);
void pidfile_unlink(void);

/* vim:set ts=3 sw=3 tw=78 et: */
