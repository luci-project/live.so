#include <stdio.h>

static int counter = 0;

const char * const hello = "Hello";

char * world() {
	fprintf(stderr,"Called world() %d times\n", counter++);
	return "World";
}

static __attribute__((constructor)) void load() {
	fputs("English version loaded\n", stderr);
}

static __attribute__((destructor)) void unload() {
	fputs("English version unloaded\n", stderr);
}
