/* darkstat 3
 * copyright (c) 2011 Emil Mikulic.
 *
 * test_addr.c: tests for addr module
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "addr.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>

void test(const char *in, const char *expect_out, int expect_result)
{
   struct addr a;
   int success, ret;
   const char *out;

   success = 1;
   ret = str_to_addr(in, &a);

   if (ret != expect_result)
      success = 0;

   if (ret == 0)
      out = addr_to_str(&a);
   else
      out = "(error)";

   if (expect_out && (strcmp(out, expect_out) != 0))
         success = 0;

   printf("%s:", success ? "PASS" : "FAIL");

   printf(" \"%s\" -> \"%s\"", in, out);
   if (expect_out && (strcmp(out, expect_out) != 0))
      printf(" (expected \"%s\")", expect_out);

   if (ret != expect_result)
      printf(" [ret %d, expected %d]", ret, expect_result);

   if (ret != 0)
      printf(" [err: %s]", gai_strerror(ret));
   
   printf("\n");
}

int main()
{
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

   return 0;
}

/* vim:set ts=3 sw=3 tw=78 et: */
