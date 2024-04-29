#include <stdio.h>

char * hello = "Hello";

char * world() {
	fputs("Called world()\n", stderr);
	return "World";
}

static __attribute__((constructor)) void load() {
	fputs("English version loaded\n", stderr);
}

static __attribute__((destructor)) void unload() {
	fputs("English version unloaded\n", stderr);
}
