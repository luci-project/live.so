#include <stdio.h>

static int counter = 0;

const char * const hello = "Hallo";

char * world() {
	fprintf(stderr, "world() %dx aufgerufen\n", counter++);
	return "Welt";
}

static __attribute__((constructor)) void load() {
	fputs("Deutsche version geladen\n", stderr);
}

static __attribute__((destructor)) void unload() {
	fputs("Deutsche version verworfen\n", stderr);
}
