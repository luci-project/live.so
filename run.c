#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

extern char * hello;
extern char * world();

int main() {
	for (unsigned i = 0; ; i++) {
		printf("%d: %s %s\n", i, hello, world());
		sleep(1);
	}
	return 0;
}
