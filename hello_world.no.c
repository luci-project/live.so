#include <stdio.h>

char * hello = "Hei";

char * world() {
	fputs("world() kalt\n", stderr);
	return "verden";
}

static __attribute__((constructor)) void load() {
	fputs("Lastet norsk versjon\n", stderr);
}

static __attribute__((destructor)) void unload() {
	fputs("Losset norsk versjon\n", stderr);
}
