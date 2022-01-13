/* darkstat 3
 * copyright (c) 2022 Emil Mikulic.
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

#include "linktypes.h"

#include <pcap/dlt.h>
#include <stdio.h>
#include <string.h>

static int retcode = 0;

static void test(int linktype, const char* expected) {
  const char* actual = get_linktype_name(linktype);
  if (strcmp(expected, actual) == 0) {
    printf("PASS: get_linktype_name(%d) = \"%s\"\n",
        linktype, expected);
  } else {
    printf("FAIL: get_linktype_name(%d) = \"%s\" (expected \"%s\")\n",
        linktype, actual, expected);
    retcode = 1;
  }
}

int main() {
  test(DLT_NULL, "DLT_NULL");
  test(DLT_EN10MB, "DLT_EN10MB");
  test(-123, "unknown");
  return retcode;
}

/* vim:set ts=2 sts=2 sw=2 tw=80 et: */
