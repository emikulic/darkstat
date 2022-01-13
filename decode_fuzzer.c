/* darkstat 3
 * copyright (c) 2022 Emil Mikulic.
 *
 * decode_fuzzer.c: fuzzer for the decoders in decode.c
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

/* Usage:
 *  clang -g -O2 -fsanitize=fuzzer,address decode_fuzzer.c -o decode_fuzzer
 *  ./decode_fuzzer decode_corpus
 *
 * Try also: -print_coverage=1
 *
 * The first two bytes of the fuzzer input are treated as the linktype, and
 * dispatch is done via getlinkhdr().
 */

#include "addr.c"
#include "decode.c"
#include "linktypes.c"

/* This is fine. It means decode_ether won't call into decode_pppoe,
 * but linktype DLT_PPP_ETHER will, so we still get coverage.
 */
int opt_want_pppoe = 0;

/* Only enable verbose if debugging the fuzzer. */
static const int verbose = 0;

void verbosef(const char *format, ...) {
  if (!verbose) return;
  va_list va;

  va_start(va, format);
  printf("verbosef: ");
  vprintf(format, va);
  printf("\n");
  va_end(va);
}

static void hexdump(const u_char *buf,
                    const uint32_t len) {
   uint32_t i;
   uint32_t col = 0;

   printf("packet of %u bytes:\n", len);
   for (i=0; i<len; i++) {
      if (col == 0) printf("  ");
      printf("%02x ", buf[i]);
      col += 3;
      if (col >= 72) {
         printf("\n");
         col = 0;
      }
   }
   if (col != 0) printf("\n");
}

static void print_summary(const struct pktsummary* s) {
  printf("pktsummary:\n");
  printf("  src=%s\n", addr_to_str(&s->src));
  printf("  dst=%s\n", addr_to_str(&s->dst));
  printf("  len=0x%04x (%d) proto=0x%02x tcp_flags=0x%02x\n",
      s->len, s->len, s->proto, s->tcp_flags);
  printf("  src_port=0x%04x (%d) dst_port=0x%04x (%d)\n",
      s->src_port, s->src_port, s->dst_port, s->dst_port);
  printf("  src_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
      s->src_mac[0],
      s->src_mac[1],
      s->src_mac[2],
      s->src_mac[3],
      s->src_mac[4],
      s->src_mac[5]);
  printf("  dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
      s->dst_mac[0],
      s->dst_mac[1],
      s->dst_mac[2],
      s->dst_mac[3],
      s->dst_mac[4],
      s->dst_mac[5]);
}

static void decode(int linktype, const uint8_t* data, size_t size) {
  const struct linkhdr *lh = getlinkhdr(linktype);
  if (verbose) {
    printf(">> linktype=%d (%s)\n", linktype, get_linktype_name(linktype));
    hexdump(data, size);
  }

  if (lh == NULL) {
    return;  /* No decoder for this linktype. */
  }

  struct pcap_pkthdr hdr;
  hdr.caplen = size;

  struct pktsummary sm;
  memset(&sm, 0, sizeof(sm));
  int ret = lh->decoder(&hdr, data, &sm);

  if (verbose) {
    printf("ret = %d\n", ret);
    if (ret) print_summary(&sm);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int16_t linktype;
  const int SZ = sizeof(linktype);
  if (size < SZ) {
    return 0;  /* Too short. */
  }
  memcpy(&linktype, data, SZ);
  decode(linktype, data + SZ, size - SZ);
  return 0;
}

/* vim:set ts=2 sw=2 sts=2 expandtab tw=78: */
