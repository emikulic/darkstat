/* darkstat 3
 *
 * db.c: load and save in-memory database from/to file
 * copyright (c) 2007-2012 Ben Stewart, Emil Mikulic.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#define _GNU_SOURCE 1 /* for O_NOFOLLOW in Linux */

#include <sys/types.h>
#include <netinet/in.h> /* for ntohs() and friends */
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "err.h"
#include "hosts_db.h"
#include "graph_db.h"
#include "db.h"

static const unsigned char export_file_header[] = {0xDA, 0x31, 0x41, 0x59};
static const unsigned char export_tag_hosts_ver1[] = {0xDA, 'H', 'S', 0x01};
static const unsigned char export_tag_graph_ver1[] = {0xDA, 'G', 'R', 0x01};

#ifndef swap64
static uint64_t swap64(uint64_t _x) {
   /* this is __bswap64 from:
    * $FreeBSD: src/sys/i386/include/endian.h,v 1.41$
    */
   return ((_x >> 56) | ((_x >> 40) & 0xff00) | ((_x >> 24) & 0xff0000) |
          ((_x >> 8) & 0xff000000) | ((_x << 8) & ((uint64_t)0xff << 32)) |
          ((_x << 24) & ((uint64_t)0xff << 40)) |
          ((_x << 40) & ((uint64_t)0xff << 48)) | ((_x << 56)));
}
#endif

#define ntoh64 hton64
static uint64_t hton64(const uint64_t ho) {
   if (ntohs(0x1234) == 0x1234)
      return ho;
   else
      return swap64(ho);
}

void
test_64order(void)
{
   static const char str[] = { 0x79,0x74,0x69,0x63,0x6b,0x72,0x65,0x6a };
   uint64_t no, ho;

   assert(sizeof(no) == 8);
   memcpy(&no, str, 8);
   ho = ntoh64(no);
   assert(ho == 8751735851613054314ULL);
   assert(hton64(ntoh64(no)) == no);
}

/* ---------------------------------------------------------------------------
 * Read-from-file helpers.  They all return 0 on failure, and 1 on success.
 */

unsigned int
xtell(const int fd)
{
   off_t ofs = lseek(fd, 0, SEEK_CUR);
   if (ofs == -1)
      err(1, "lseek(0, SEEK_CUR) failed");
   return (unsigned int)ofs;
}

/* Read <len> bytes from <fd>, warn() and return 0 on failure,
 * or return 1 for success.
 */
int
readn(const int fd, void *dest, const size_t len)
{
   ssize_t numread;

   numread = read(fd, dest, len);
   if (numread == (ssize_t)len) return 1;

   if (numread == -1)
      warn("at pos %u: couldn't read %d bytes", xtell(fd), (int)len);
   else
      warnx("at pos %u: tried to read %d bytes, got %d",
         xtell(fd), (int)len, (int)numread);
   return 0;
}

/* Read a byte. */
int
read8(const int fd, uint8_t *dest)
{
   assert(sizeof(*dest) == 1);
   return readn(fd, dest, sizeof(*dest));
}

/* Read a byte and compare it to the expected data.
 * Returns 0 on failure or mismatch, 1 on success.
 */
int
expect8(const int fd, uint8_t expecting)
{
   uint8_t tmp;

   assert(sizeof(tmp) == 1);
   if (!readn(fd, &tmp, sizeof(tmp))) return 0;
   if (tmp == expecting) return 1;

   warnx("at pos %u: expecting 0x%02x, got 0x%02x",
      xtell(fd)-1, expecting, tmp);
   return 0;
}

/* Read a network order uint16_t from a file
 * and store it in host order in memory.
 */
int
read16(const int fd, uint16_t *dest)
{
   uint16_t tmp;

   assert(sizeof(tmp) == 2);
   if (!read(fd, &tmp, sizeof(tmp))) return 0;
   *dest = ntohs(tmp);
   return 1;
}

/* Read a network order uint32_t from a file
 * and store it in host order in memory.
 */
int
read32(const int fd, uint32_t *dest)
{
   uint32_t tmp;

   assert(sizeof(tmp) == 4);
   if (!read(fd, &tmp, sizeof(tmp))) return 0;
   *dest = ntohl(tmp);
   return 1;
}

/* Read an IPv4 addr from a file.  This is for backward compatibility with
 * host records version 1 and 2.
 */
int
readaddr_ipv4(const int fd, struct addr *dest)
{
   dest->family = IPv4;
   return readn(fd, &(dest->ip.v4), sizeof(dest->ip.v4));
}

/* Read a struct addr from a file.  Addresses are always stored in network
 * order, both in the file and in the host's memory (FIXME: is that right?)
 */
int
readaddr(const int fd, struct addr *dest)
{
   unsigned char family;

   if (!read8(fd, &family))
      return 0;

   if (family == 4) {
      dest->family = IPv4;
      return readn(fd, &(dest->ip.v4), sizeof(dest->ip.v4));
   }
   else if (family == 6) {
      dest->family = IPv6;
      return readn(fd, dest->ip.v6.s6_addr, sizeof(dest->ip.v6.s6_addr));
   }
   else
      return 0; /* no address family I ever heard of */
}

/* Read a network order uint64_t from a file
 * and store it in host order in memory.
 */
int
read64(const int fd, uint64_t *dest)
{
   uint64_t tmp;

   assert(sizeof(tmp) == 8);
   if (!read(fd, &tmp, sizeof(tmp))) return 0;
   *dest = ntoh64(tmp);
   return 1;
}

/* ---------------------------------------------------------------------------
 * Write-to-file helpers.  They all return 0 on failure, and 1 on success.
 */

/* Write <len> bytes to <fd>, warn() and return 0 on failure,
 * or return 1 for success.
 */
int
writen(const int fd, const void *dest, const size_t len)
{
   ssize_t numwr;

   numwr = write(fd, dest, len);
   if (numwr == (ssize_t)len) return 1;

   if (numwr == -1)
      warn("couldn't write %d bytes", (int)len);
   else
      warnx("tried to write %d bytes but wrote %d",
         (int)len, (int)numwr);
   return 0;
}

int
write8(const int fd, const uint8_t i)
{
   assert(sizeof(i) == 1);
   return writen(fd, &i, sizeof(i));
}

/* Given a uint16_t in host order, write it to a file in network order.
 */
int
write16(const int fd, const uint16_t i)
{
   uint16_t tmp = htons(i);
   assert(sizeof(tmp) == 2);
   return writen(fd, &tmp, sizeof(tmp));
}

/* Given a uint32_t in host order, write it to a file in network order.
 */
int
write32(const int fd, const uint32_t i)
{
   uint32_t tmp = htonl(i);
   assert(sizeof(tmp) == 4);
   return writen(fd, &tmp, sizeof(tmp));
}

/* Given a uint64_t in host order, write it to a file in network order.
 */
int
write64(const int fd, const uint64_t i)
{
   uint64_t tmp = hton64(i);
   assert(sizeof(tmp) == 8);
   return writen(fd, &tmp, sizeof(tmp));
}


/* Write the active address part in a struct addr to a file.
 * Addresses are always stored in network order, both in the file and
 * in the host's memory (FIXME: is that right?)
 */
int
writeaddr(const int fd, const struct addr *const a)
{
   if (!write8(fd, a->family))
      return 0;

   if (a->family == IPv4)
      return writen(fd, &(a->ip.v4), sizeof(a->ip.v4));
   else {
      assert(a->family == IPv6);
      return writen(fd, a->ip.v6.s6_addr, sizeof(a->ip.v6.s6_addr));
   }
}

/* ---------------------------------------------------------------------------
 * db import/export code follows.
 */

/* Check that the global file header is correct / supported. */
int
read_file_header(const int fd, const uint8_t expected[4])
{
   uint8_t got[4];

   if (!readn(fd, got, sizeof(got))) return 0;

   /* Check the header data */
   if (memcmp(got, expected, sizeof(got)) != 0) {
      warnx("bad header: "
         "expecting %02x%02x%02x%02x, got %02x%02x%02x%02x",
         expected[0], expected[1], expected[2], expected[3],
         got[0], got[1], got[2], got[3]);
      return 0;
   }
   return 1;
}

/* Returns 0 on failure, 1 on success. */
static int
db_import_from_fd(const int fd)
{
   if (!read_file_header(fd, export_file_header)) return 0;
   if (!read_file_header(fd, export_tag_hosts_ver1)) return 0;
   if (!hosts_db_import(fd)) return 0;
   if (!read_file_header(fd, export_tag_graph_ver1)) return 0;
   if (!graph_import(fd)) return 0;
   return 1;
}

void
db_import(const char *filename)
{
   int fd = open(filename, O_RDONLY | O_NOFOLLOW);
   if (fd == -1) {
      warn("can't import from \"%s\"", filename);
      return;
   }
   if (!db_import_from_fd(fd)) {
      warnx("import failed");
      /* don't stay in an inconsistent state: */
      hosts_db_reset();
      graph_reset();
   }
   close(fd);
}

/* Returns 0 on failure, 1 on success. */
static int
db_export_to_fd(const int fd)
{
   if (!writen(fd, export_file_header, sizeof(export_file_header)))
      return 0;
   if (!writen(fd, export_tag_hosts_ver1, sizeof(export_tag_hosts_ver1)))
      return 0;
   if (!hosts_db_export(fd))
      return 0;
   if (!writen(fd, export_tag_graph_ver1, sizeof(export_tag_graph_ver1)))
      return 0;
   if (!graph_export(fd))
      return 0;
   return 1;
}

void
db_export(const char *filename)
{
   int fd = open(filename, O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC, 0600);
   if (fd == -1) {
      warn("can't export to \"%s\"", filename);
      return;
   }
   verbosef("exporting db to file \"%s\"", filename);
   if (!db_export_to_fd(fd))
      warnx("export failed");
   else
      verbosef("export successful");

   /* FIXME: should write to another filename and use the rename() syscall to
    * atomically update the output file on success
    */
   close(fd);
}

/* vim:set ts=3 sw=3 tw=78 et: */
