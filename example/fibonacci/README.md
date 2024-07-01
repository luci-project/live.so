Fibonacci example
=================

This directory contains six versions of a shared library calculating the Fibonacci sequence, all sharing the [same interface (API)](fib.h):

 * [`fib_1`](fib_1.c) uses the well-known recursive algorithm with exponential time complexity O(n²)
 * [`fib_2`](fib_2.c) uses dynamic programming with linear time complexity O(n), which is noticeably faster.
 * [`fib_3`](fib_3.c) employs a more space-efficient iterative algorithm with linear time complexity O(n).
 * [`fib_4`](fib_4.c) is based on a matrix algorithm with logarithmic time complexity O(log(n)) – while there shouldn't be any perceptible difference compared to the iterative approach, this example demonstrates that new helper functions can be introduced as well.
 * [`fib_5`](fib_5.c) implements Binet's formula (using the golden ratio) and therefore has constant time complexity O(1) – since this example requires math functions like square root, the library itself is linked against `libm.so`, therefore demonstrates *Luci*'s ability to handle versions with changed dependencies or its usage of new external functions.
 * [`fib_6`](fib_6.c) contains a lookup table with all relevant Fibonacci sequence numbers, having a constant time complexity O(1) while being slightly faster than the previous version. This version illustrates that changing/introducing (non-writable) data does not pose an issue for *Luci*.

(all versions are based on the examples at [geeksforgeeks.org](https://www.geeksforgeeks.org/program-for-nth-fibonacci-number/))


The [`run-main`](main.c) binary will employ the shared library interface to calculate Fibonacci numbers (endless loop, but only the first 93 values will be valid due to overflows).
To relax the CPU, it will wait a second in between calculating the next number (can be changed/disabled using the `DELAY` macro).


Preparation
-----------

Build all libraries and binaries with

    make

This will create the two executables (prefixed with `run-`) and a subfolder for each library version, containing the corresponding `libfib.so` file – and a symlink to the first version in the base directory, which is used by the binaries.

You can also change the compiler (e.g., `make CC=clang` for LLVM) or adjust the compiler flags (`CFLAGS=...`).
Have a look at the [Makefile](Makefile) for more details.

The `main` executable will use `libfib.so`, which is by default a symbolic link to the first version of the library (`fib_1`), hence the output will look similar to

    fib(0) = 0
    [using Fibonacci library v1: O(2^n))]
    fib(1) = 1
    [using Fibonacci library v1: O(2^n))]
    fib(2) = 1
    [using Fibonacci library v1: O(2^n))]

When calculating the 50th+ Fibonacci number, this version will take a significant amount of time (several dozens of seconds).


Dynamic Updates
---------------

If you just want to see a quick demonstration, just run

    ./demo.sh


Or do it manually:
Restart the example with dynamic updates enabled:

    LD_PRELOAD=$(readlink -f ../../luci.so) ./run-main

After a certain time in a different terminal window (but same working directory), simulate an *update* of the Fibonacci library by changing the symbolic link:

    ln -sf fib_2/libfib.so

*Luci* will now detect the change, checking if the new version is compatible with the old one, and then load and relink it.
If a call to `fib` is executed during the update, it will finish in library version 1, but subsequent calls will be made in the corresponding function of library version 2 - you should notice a significant performance boost and a different output in the lines starting with square brackets:

    fib(43) = 433494437
    [using Fibonacci library v1: O(2^n))]
    fib(44) = 701408733
    [using Fibonacci library v1: O(2^n))]
    fib(45) = 1134903170
    [using Fibonacci library v2: O(n)]
    fib(46) = 1836311903
    [using Fibonacci library v2: O(n)]

In the same way, you can also change to any other version (e.g., `ln -sf fib_3/libfib.so`).
It is not necessary to sequentially increase the versions; you can directly apply version 6. For example, here an output running `run-measure` with two consecutive updates:

    fib(44) = 701408733 (in 1.574935s)
    [using Fibonacci library v1: O(2^n))]
    fib(45) = 1134903170 (in 2.627559s)
    [using Fibonacci library v1: O(2^n))]
    fib(46) = 1836311903 (in 4.181815s)
    [using Fibonacci library v2: O(n))]
    fib(47) = 2971215073 (in 0.000001s)
    [using Fibonacci library v2: O(n))]
    fib(48) = 4807526976 (in 0.000038s)
    [using Fibonacci library v6: O(1)]
    fib(49) = 7778742049 (in 0.000001s)
    [using Fibonacci library v6: O(1)]

If you want to see further details about the dynamic linking, increase `LIVE_LOGLEVEL` (e.g., `4` for debugging).


Notes on RELRO
--------------

The example employs the [full relocation read-only (RELRO)](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro) for the libraries in the `Makefile`s `LDFLAGS`.
This common mitigation technique places the global offset table (GOT) completely in the non-writable section, requiring to bind all references on load-time (`BIND_NOW`).
Without full RELRO, calling new functions (like the math functions `sqrtl` and `powl` in `fib_5`) would not be possible because it changes the size of the GOT (➔ different writable section makes it incompatible).

In addition, the default compiler flags might include `-fstack-protector`, which will result in calls to `__stack_chk_fail` in some versions, having the same effect on the GOT.
While there is a big chance that this would be always present in bigger libraries, our example libraries are tiny and therefore this GOT entry might be omitted if the code does not contain any functions with arrays on the stack.

In LLVM, a similar case might happen with the recursion in `fib` (in the first version), which will allocate an extra GOT slot.

Without full RELRO (by omitting `BIND_NOW` / no `-z now` linker flag), GCC 11 would only have 27% compatible updates and 40% with clang/LLVM 14 (on Ubuntu Jammy) due to the reasons described above.

Nevertheless, while the described *unintended* incompatibilities are quite likely in very small libraries like the provided examples, we have observed they are rather seldom in real-world libraries — even without hardening techniques like RELRO.
