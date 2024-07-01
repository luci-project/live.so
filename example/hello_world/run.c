#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

extern unsigned versions;
extern char * hello;
extern char * world();

int main() {
	const char * prefix = "run";
	int delay = 1;
	for (unsigned i = 0; i < 30 ; i++) {
		if (i == 13) {
			puts("Forking!");
			if (fork() == 0) {
				prefix = "parent";
			} else {
				prefix = "child";
				delay = 2;
			}
		}
		printf("%s %d: %s %s\n", prefix, i, hello, world());
		sleep(delay);
	}
	printf("%s done - %d versions loaded!\n", prefix, versions);
	return 0;
}
