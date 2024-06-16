#include <stdio.h>

static int counter = 0;

const char * const hello = "Hola";

char * world() {
	fputs("Llamado world()\n", stderr);
	counter++;
	return "mundo";
}

static __attribute__((constructor)) void load() {
	fputs("version cargada en espanola\n", stderr);
}

static __attribute__((destructor)) void unload() {
	fputs("Descargado version espanola\n", stderr);
}
