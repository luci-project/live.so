#include <stdio.h>

unsigned versions = 0;
static int counter = 0;

const char * const hello = "Hola";
const char * const lang = "espanola";

char * world() {
	fputs("Llamado world()\n", stderr);
	counter++;
	return "mundo";
}

static __attribute__((constructor)) void load() {
	fprintf(stderr, "version cargada en %s\n", lang);
	versions++;
}

static __attribute__((destructor)) void unload() {
	fprintf(stderr, "Descargado version %s\n", lang);
}
