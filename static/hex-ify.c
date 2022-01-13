/* Convert a binary file to a const char array of hex. */
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
  int c, eol;
  if (argc != 2) {
    fprintf(stderr, "usage: %s name <infile >outfile.h\n",
      argv[0]);
    exit(EXIT_FAILURE);
  }
  printf("/* this file was automatically generated with hex-ify */\n"
         "static const unsigned char %s[] = {\n", argv[1]);
  int start_of_line = 1;
  int first = 1;
  int bytes = 0;
  while ((c = getchar()) != EOF) {
    if (start_of_line) {
      printf("  ");
      start_of_line = 0;
    }
    if (first) {
      first = 0;
    } else {
      printf(", ");
    }
    printf("0x%02x", (unsigned char)c);
    bytes++;
    if (bytes == 12) {
      printf(",\n");
      first = 1;
      start_of_line = 1;
      bytes = 0;
    }
  }
  printf("\n};\n");
  return (0);
}
