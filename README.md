
live.so
=======

Implementation of the [Luci approach](https://www.usenix.org/conference/atc23/presentation/heinloth) as a preloadable shared object for the Glibc RTLD (basically any major Linux distribution):
By setting `LD_PRELOAD` to the absolute path of `live.so`, file system changes of other loaded shared objects will be tracked and updated at runtime if compatible.
The main criteria for compatibility is that the layout of the global writable data is identical and no data structures have changed.
Therefore, the focus is on code changes (which covers many bug fixes).


## Usage

Build `live.so` by running

	make

It requires the [elfutils](https://sourceware.org/elfutils/) libraries (Debian/Ubuntu package `libelf-dev`) to be installed.

Let's assume you have a (Glibc) program `bin` that is linked to shared object `libfoo.so.1` (using a symbolic link `libfoo.so`).
You can preload this shared library with

	LD_PRELOAD=$(readlink -f live.so) path/to/bin

Now you can modify the library by changing the symlink to point to an updated version `libfoo.so.2` during the execution of the program.
Within seconds, all library calls will now call code from the second version instead of the first.

Since the global writable data is shared, all variables will retain their contents during the update.


## Examples

This project comes with two examples to demonstrate the approach:

 * [Hello World](example/hello_world) exchanges the shared library that provides the "hello world" string with versions in different languages.
 * [Fibonacci](example/fibonacci) is identical to the [Luci RTLD example](https://github.com/luci-project/luci/tree/master/example) and dynamically replaces the algorithms for computing Fibonacci numbers.


## Limitations

This version has the same conceptual limitations as the [Luci RTLD](https://github.com/luci-project/luci/):
For example, unless you are using [full RELRO](https://www.redhat.com/de/blog/hardening-elf-binaries-using-relocation-read-only-relro), you may not introduce new functions from shared objects (including the Glibc) as this would alter the [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table), which is located in the global writable data section.

However, since this version is mostly indented as a proof of concept, it has some additional limitations compared to the Luci RTLD:
For example, it cannot update dynamically loaded shared objects (via `dlopen`).
Other missing features include the inability of dealing with direct changes to the shared library and to detect outdated code.


## Author & License

The *Luci* project is being developed by [Bernhard Heinloth](https://sys.cs.fau.de/person/heinloth) of the [Department of Computer Science 4](https://sys.cs.fau.de/) at [Friedrich-Alexander-Universität Erlangen-Nürnberg](https://www.fau.eu/) and is available under the [GNU Affero General Public License, Version 3 (AGPL v3)](LICENSE.md).
