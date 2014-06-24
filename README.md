# `eld`

`eld` is a minimal dynamic loader for ELF shared objects.

## Building

    mkdir eld
    cd eld
    git clone ... src
    mkdir build
    cd build
    cmake ../src/ -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_C_COMPILER="$INSTALL_PATH/bin/clang" \
        -DCMAKE_C_FLAGS="-target or1k-elf" \
        -DOR1K_SIM_PATH="$INSTALL_PATH/bin/or32-elf-sim" \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH/or1k-elf"
    make

## Components

### `libeld.a`

This is the core dynamic loading library. It exposes the classical `dlopen`,
`dlclose` and `dlsym` functions. They work pretty much as expected, except for
the fact that the file name provided to `dlopen` must be a pointer to the buffer
of memory where the ELF to load is located.

To try it out, create a C file, name it `libyour.c` and make it a shared
library:

    int your() {
      return 99;
    }

    $ clang -target or1k-elf libyour.c -shared -o libyour.so

Convert the ELF shell object (`.so` file) in a C array with `xxd`:

    $ xxd -i libyour.so > libyour.so.h
    $ cat libyour.so.h
    unsigned char libmy_so[] = {
      0x7f, 0x45, 0x4c, 0x46, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ...

Then include it in your main C file (`main.c`) and call `dlopen` on the
generated array:

    #include <stdlib.h>
    #include <stdio.h>
    #include "dl.h"
    #include "libyour.so.h"

    typedef int (*myfunc_ptr)();

    int main() {
      void *handle = NULL;

      handle = dlopen((char *) libyour_so, 0);

      if (!handle) {
        printf("Couldn't load the dynamic library\n");
        return EXIT_FAILURE;
      }

      myfunc_ptr your = dlsym(handle, "your");

      if (!your) {
        printf("Couldn't find the symbol \"your\"\n");
        return EXIT_FAILURE;
      }

      printf("your() == %d\n", your());

      return EXIT_SUCCESS;
    }

Supposing you are working the `eld` build directory:

    $ clang -target or1k-elf -I. main.c -L. -leld -o main -Wl,--export-dynamic
    $ or32-elf-sim -f sim.cfg main
    ...
    your() == 99
    ...

### libyour.so, libmy.so and loader

The project provides some example libraries and a simple application to test the
loader.

* `loader` (`test.c`): reads from standard input a series of libraries, loads
  them and performs some simple operations using `eld`; libraries are fed into
  the loader once at a time, first sending an integer (4-byte, little endian)
  representing the size of the library, and then the library itself; repeat
  until a 0-sized library is fed in input. This process is facilitated by
  `feed-so.py` script.
* `libyour.so` (`libyour.c`): contains just a single function and a global
  variable;
* `libmy.so` (`libmy.c`): depends on `libyour.so` and uses its function, has a
  constructor and a destructor, and expects to have some functions from the
  libc.

There is a target to build and test with `or1ksim` the loader:

    make loader_sim

Or if you want to launch `or1ksim` in debug mode:

    make loader_sim_debug

## Supported platforms

`eld` primary aim is currently supporting bare-metal OpenRISC targets. `eld` has
been tested with both clang and GCC and works fine with both `or1k-elf` and
`or1kle-elf` targets.

## Current limitations

When applying resolving symbols in shared object or calling `dlsym`, the symbols
are not searched in the proper order. Currently we first search in the shared
object currently being relocated (or the handle passed to `dlsym`) and then all
the previously loaded shared objects are searched in load order.

## TODO

* Isolate platform specific parts
* Move examples to a dedicated directory
* Add CMake target to generate documentation
* Import `sys/queue.h`
* Add support for PID objects
* Add support for TLS relocations
