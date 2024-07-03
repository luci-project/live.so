Hello World example
===================

There are four variants of the `libhw.so` shared library:
 * English
 * German
 * Norwegian
 * Spanish

All of them provide both a symbol for a constant string `hello` and a function `world()`, however both are different in each version.
Compile them by running

	make

The program `run` will use the shared library to get the contents of the constant string `hello` and call the function `world` in a loop (30 times, with 1 second delay in between).
In addition, the program will do a `fork` after 13 seconds.

To test the update, either use the [Makefile](example/hello_world/Makefile) target `test`, which will exchange the shared library with a different version every 5 seconds

	make test

or manually by executing the program with `live.so` preloaded

	LD_PRELOAD=$(readlink -f ../../live.so) ./run

while adjusting the symbolic link to the shared library at the same time

	ln -f -s libhw-de.so libhw.so
	sleep 5
	ln -f -s libhw-en.so libhw.so

Set the `LIVE_LOGLEVEL` environment variable to `4` for debug output
