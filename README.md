# eld

eld is a minimal dynamic loader for ELF shared objects.

## Current limitations

When applying resolving symbols in shared object or calling dlsym, the symbols
are not searched in the proper order. Currently we first search in the shared
object currently being relocated (or the handle passed to dlsym) and then all
the previously loaded shared objects are searched in load order.

## TODO

* Import sys/queue.h
* Add support for having different address spaces
* Add support for TLS relocations
* Let eld_init and eld_finish be called from crt
* Documentation
