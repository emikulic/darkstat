/* DON'T LOOK AT MY FACE!  MY HIDEOUS FACE! */
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
	printf("/* this file was automatically generated */\n"
	       "static char %s[] =", argv[1]);
	eol = 1;
	while ((c = getchar()) != EOF) {
		if (eol) {
			printf("\n\"");
			eol = 0;
		}
		switch (c) {
		case '\n': printf("\\n\""); eol = 1; break;
		case '"': printf("\\\""); break;
		case '\\': printf("\\\\"); break;
		default: putchar(c);
		}
	}
	printf(";\n"
	       "static const size_t %s_len = sizeof(%s) - 1;\n",
	       argv[1], argv[1]);
	return (0);
}
