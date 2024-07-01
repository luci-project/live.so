#include <stdio.h>

unsigned versions = 0;
static int counter = 0;

const char * const hello = "Hello";

char * world() {
	fprintf(stderr,"Called world() %d times\n", counter++);
	return "World";
}

static void lang() {
	fputs("English version", stderr);
}

static __attribute__((constructor)) void load() {
	lang();
	fputs(" loaded\n", stderr);
	versions++;
}

static __attribute__((destructor)) void unload() {
	lang();
	fputs(" unloaded\n", stderr);
}
