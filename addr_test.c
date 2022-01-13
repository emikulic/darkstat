/* darkstat 3
 * copyright (c) 2011 Emil Mikulic.
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
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "addr.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>

static int retcode = 0;

static void test(const char *in, const char *expect_out, int expect_result) {
  struct addr a;
  int success, ret;
  const char *out;

  success = 1;
  ret = str_to_addr(in, &a);

  if (ret != expect_result) {
    success = 0;
  }

  if (ret == 0) {
    out = addr_to_str(&a);
  } else {
    out = "(error)";
  }

  if (expect_out && (strcmp(out, expect_out) != 0)) {
    success = 0;
  }

  printf("%s:", success ? "PASS" : "FAIL");

  printf(" \"%s\" -> \"%s\"", in, out);
  if (expect_out && (strcmp(out, expect_out) != 0)) {
    printf(" (expected \"%s\")", expect_out);
  }

  if (ret != expect_result) {
    printf(" [ret %d, expected %d]", ret, expect_result);
  }

  if (ret != 0) {
    printf(" [err: %s]", gai_strerror(ret));
  }

  printf("\n");

  if (!success) {
    retcode = 1;
  }
}

void test_inside(const char *a, const char *net, const char *mask, int expect)
{
  struct addr aa, anet, amask;

  str_to_addr(a, &aa);
  str_to_addr(net, &anet);
  str_to_addr(mask, &amask);

  printf("%s: %s in %s/%s\n",
      addr_inside(&aa, &anet, &amask) ? "PASS" : "FAIL",
      a, net, mask);
}

int main() {
  test("0.0.0.0", "0.0.0.0", 0);
  test("192.168.1.2", "192.168.1.2", 0);

  test("::", "::", 0);
  test("::0", "::", 0);
  test("::00", "::", 0);
  test("::000", "::", 0);
  test("::0000", "::", 0);

  test("::1", "::1", 0);
  test("::01", "::1", 0);
  test("::001", "::1", 0);
  test("::0001", "::1", 0);

  test("2404:6800:8004::68", "2404:6800:8004::68", 0);
  test("2404:6800:8004:0000:0000:0000:0000:0068", "2404:6800:8004::68", 0);

  test(".", NULL, EAI_NONAME);
  test(":", NULL, EAI_NONAME);
  test("23.75.345.200", NULL, EAI_NONAME);

  test_inside("192.168.1.2", "192.168.0.0", "255.255.0.0", 1);
  test_inside("2001:0200::3eff:feb1:44d7",
      "2001:0200::",
      "ffff:ffff::", 1);

  return retcode;
}

/* vim:set ts=2 sts=2 sw=2 tw=80 et: */
