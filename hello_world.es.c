#include <stdio.h>

char * hello = "Hola";

char * world() {
	fputs("Llamado world()\n", stderr);
	return "mundo";
}

static __attribute__((constructor)) void load() {
	fputs("version cargada en espanola\n", stderr);
}

static __attribute__((destructor)) void unload() {
	fputs("Descargado version espanola\n", stderr);
}
