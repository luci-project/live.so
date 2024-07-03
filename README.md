live.so
=======

Implementation of the [Luci approach](https://www.usenix.org/conference/atc23/presentation/heinloth) as a preloadable shared object for the [glibc](https://www.gnu.org/software/libc/) RTLD (basically any major Linux distribution):
By setting `LD_PRELOAD` to the absolute path of `live.so`, file system changes of other loaded shared objects will be tracked and updated at runtime if compatible.
The main criteria for compatibility is that the layout of the global writable data is identical and no data structures have changed.
Therefore, the focus is on code changes (which covers many bug fixes).


## Usage

Build `live.so` by running

	make

It requires the [elfutils](https://sourceware.org/elfutils/) libraries (Debian/Ubuntu package `libelf-dev`) to be installed.

Let's assume you have a (glibc) program `bin` that is linked to shared object `libfoo.so.1` (using a symbolic link `libfoo.so`).
You can preload this shared library with

	LD_PRELOAD=$(readlink -f live.so) path/to/bin

Now you can modify the library by changing the symlink to point to an updated version `libfoo.so.2` during the execution of the program.
Within seconds, all library calls will now call code from the second version instead of the first.

Since the global writable data is shared, all variables will retain their contents during the update.


## Examples

This project comes with two examples to demonstrate the approach:

 * [Hello World](example/hello_world) exchanges the shared library that provides the "hello world" string with versions in different languages.
 * [Fibonacci](example/fibonacci) is identical to the [Luci RTLD example](https://github.com/luci-project/luci/tree/master/example) and dynamically replaces the algorithms for computing Fibonacci numbers.


## Concept (in a nutshell)

When compiling a program that uses [shared libraries](https://en.wikipedia.org/wiki/Shared_library), the linker cannot determine the address of its variables and functions because this is done at runtime (e.g., for [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)).
Therefore, when a program accesses an external variable or calls an external function, it uses the [global offset table (GOT)](https://en.wikipedia.org/wiki/Global_Offset_Table) as an indirection.
The [dynamic linker/loader](https://en.wikipedia.org/wiki/Dynamic_linker) prepares this table at program startup with the address of the shared library in the process virtual memory.

And if the shared library is changed, e.g. due to a bug, all programs using it must be restarted.
With *live.so*, this can be omitted:

This library analyzes all shared libraries used by the program before executing the `main` function and monitors file system changes (via [`inotify`](https://man7.org/linux/man-pages/man7/inotify.7.html)) of the libraries.
If a newer version is found, *live.so* loads it into the [process virtual memory](https://en.wikipedia.org/wiki/Virtual_memory) (via [`dlopen`](https://man7.org/linux/man-pages/man3/dlopen.3.html)) and updates the GOT.

     PROGRAM          GOT             SYMLINK          SHARED LIB
    
    while(1) {      ┌───────┐
      var++; ─────► │var ───┼──┬───► libfoo.so ──┐--- libfoo.so.1
      func(); ────► │func ──┼──┘                 └──► libfoo.so.2
      sleep(1); ──► │sleep ─┼───────────────────────► libc.so.6
    }               └───────┘

All subsequent calls to the shared library will now be handled by the newer version.

Neither the program nor the shared library need to be prepared for the update:
Since shared libraries use [position-independent code](https://en.wikipedia.org/wiki/Position-independent_code), the memory image remains unchanged and is exactly as the compiler & linker intended - no code patching is required.
This means that you can change the code in any way you like, as long as the external interface ([API](https://en.wikipedia.org/wiki/API)) remains the same.

Since shared libraries may have an internal state, the new version of the shared library should use it as well.
With this approach not supporting data modification, the [data segment](https://en.wikipedia.org/wiki/Data_segment) is identical to its predecessor.
Accordingly, *live.so* creates a memory alias for this segment, allowing old and new code to work on the same data.

              Process's virtual memory
                     ┌───────┐
        PROGRAM code │█████▀▀│
                data │▄▄▄▄ ▀▀│
                     │  ...  │
    libfoo.so.1 code │███▀▀▀▀│
                data │▄▄████▀│ ──┐
                     │  ...  │   │ memory
    libfoo.so.2 code │██████▀│   │ alias
                data │▄▄████▀│ ◄─┘
                     └───────┘

No quiescence is required, but the update can happen at any time:
If the program is currently executing code in the old shared library, this will not prevent the update.
Instead, there will be a concurrent update of the GOT.
And except for loading the newer version into virtual memory, there is no runtime overhead.

For further information, have a look at [Luci RTLD](https://github.com/luci-project/luci/) and our [paper](https://sys.cs.fau.de/publications/2023/heinloth_23_atc.pdf) and [poster](https://sys.cs.fau.de/publications/2023/heinloth_23_atc-poster.pdf).


## Limitations

This version has the same conceptual limitations as the [Luci RTLD](https://github.com/luci-project/luci/):
For example, unless you are using [full RELRO](https://www.redhat.com/de/blog/hardening-elf-binaries-using-relocation-read-only-relro), you may not introduce new functions from shared objects (including the glibc) as this would alter the [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table), which is located in the global writable data section.

However, since this version is mostly indented as a proof of concept, it has some additional limitations compared to the Luci RTLD:
For example, it cannot update dynamically loaded shared objects (via `dlopen`).
Other missing features include the inability of dealing with direct changes to the shared library and to detect outdated code.


## Advantages

So, why bother and creat this project if [Luci RTLD](https://github.com/luci-project/luci/) seems to be superior?
Well, unlike the RTLD this can easily be used on other architectures, since it does not have any CPU-specific instructions or relocations.
It should work on any system with a Linux userspace based on a recent [Glibc](https://www.gnu.org/software/libc/).


## Author & License

The *Luci* project is being developed by [Bernhard Heinloth](https://sys.cs.fau.de/person/heinloth) of the [Department of Computer Science 4](https://sys.cs.fau.de/) at [Friedrich-Alexander-Universität Erlangen-Nürnberg](https://www.fau.eu/) and is available under the [GNU Affero General Public License, Version 3 (AGPL v3)](LICENSE.md).
