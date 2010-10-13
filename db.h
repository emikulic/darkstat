/* darkstat 3
 *
 * db.h: load and save in-memory database from/to file
 * copyright (c) 2007 Ben Stewart, Emil Mikulic.
 */

#include "hosts_db.h"   /* addr46 */

void db_import(const char *filename);
void db_export(const char *filename);

/* byteswap */
uint64_t hton64(const uint64_t ho);
uint64_t ntoh64(const uint64_t no);
void test_64order(void);

/* read helpers */
unsigned int xtell(const int fd);
int readn(const int fd, void *dest, const size_t len);
int read8(const int fd, uint8_t *dest);
int expect8(const int fd, uint8_t expecting);
int read16(const int fd, uint16_t *dest);
int read32(const int fd, uint32_t *dest);
int readaddr(const int fd, struct addr46 *dest);
int read64(const int fd, uint64_t *dest);
int read_file_header(const int fd, const uint8_t expected[4]);

/* write helpers */
int writen(const int fd, const void *dest, const size_t len);
int write8(const int fd, const uint8_t i);
int write16(const int fd, const uint16_t i);
int write32(const int fd, const uint32_t i);
int writeaddr(const int fd, const struct addr46 *const addr);
int write64(const int fd, const uint64_t i);

/* vim:set ts=3 sw=3 tw=78 et: */
