/* darkstat 3
 * copyright (c) 2022 Emil Mikulic.
 *
 * linktypes.c: convert pcap linktype to a string name.
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

#include <pcap/dlt.h>

struct linktype_pair {
  int linktype;  /* Returned by pcap_datalink(). */
  const char* name;
};

#define LT(name) { name, #name },
static const struct linktype_pair linktypes[] = {
#include "linktypes_list.h"
};
#undef LT

const char* get_linktype_name(int linktype) {
  const int n = sizeof(linktypes) / sizeof(*linktypes);
  for (int i = 0; i < n; i++) {
    if (linktypes[i].linktype == linktype) return linktypes[i].name;
  }
  return "unknown";
}

/* vim:set ts=2 sts=2 sw=2 tw=80 et: */
