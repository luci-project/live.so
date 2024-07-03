#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern unsigned versions;
extern char * hello;
extern char * world();

int main(int argc, char * argv[]) {
	const char * prefix = "run";
	int delay = 1;

	int runs = -1;
	int fork_run = -1;

	if (argc > 1)
		runs = atoi(argv[1]);
	if (argc > 2)
		fork_run = atoi(argv[2]);

	for (int i = 1; runs < 0 || i <= runs ; i++) {
		if (i == fork_run) {
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
