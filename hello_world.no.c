#include <stdio.h>

static int counter = 0;

const char * const hello = "Hei";

char * world() {
	fprintf(stderr, "world() kalt %dx\n", counter++);
	return "verden";
}

static __attribute__((constructor)) void load() {
	fputs("Lastet norsk versjon\n", stderr);
}

static __attribute__((destructor)) void unload() {
	fputs("Losset norsk versjon\n", stderr);
}
