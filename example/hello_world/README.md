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

The program `run` will use the shared library to get the contents of the constant string `hello` and call the function `world` in a loop (with 1 second delay in between).
An optional first parameter limits the number of loops, while a second parameter will specify the loop in which the program calls `fork` (with the child then waits 2 seconds after each loop).

To test the update, either use the [Makefile](example/hello_world/Makefile) target `test` for a one minute demonstration, which will exchange the shared library with a different version every 5 seconds and `fork` after 13 seconds

	make test

or manually by executing the program with `live.so` preloaded

	LD_PRELOAD=$(readlink -f ../../live.so) ./run

while adjusting the symbolic link to the shared library at the same time

	ln -f -s libhw-de.so libhw.so
	sleep 5
	ln -f -s libhw-en.so libhw.so

For debug output set the `LIVE_LOGLEVEL` environment variable to `4`.
