#include <stdio.h>

char * hello = "Hallo";

char * world() {
	fprintf(stderr, "world() aufgerufen\n");
	return "Welt";
}

static __attribute__((constructor)) void load() {
	fputs("Deutsche version geladen\n", stderr);
}

static __attribute__((destructor)) void unload() {
	fputs("Deutsche version verworfen\n", stderr);
}
