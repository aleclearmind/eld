#ifndef DL_H
#define DL_H

/* Some macros to add support for prefixing dl* functions */
#ifdef DL_PREFIX
#  define NAME2(prefix, name) prefix ## _ ## name
#  define NAME1(prefix, name) NAME2(prefix, name)
#  define PREFIX(name) NAME1(DL_PREFIX, name)
#else
#  define PREFIX(name) name
#endif

/**
 * Return the address of a dynamic symbol
 *
 * @param handle reference to library to search in. If NULL, the search will be
 * performed over all the loaded libraries.
 * @param symbol NULL-terminated string of the dynamic symbol to search.
 *
 * @return the address of the requested symbol, or NULL if not found.
 */
void *PREFIX(dlsym)(void *handle, char *symbol);

/**
 * Load the specified shared library.
 *
 * @param filename pointer to the library to load. Note that this is not a file
 * name (since we assume not to have a file system), but it's the library
 * itself, a bit as the "data:" URLs work.
 * @param flag flags to use while loading the library. Currently this parameter
 * has no effect.
 *
 * @return an handle to the loaded library, which can be later used with dlsym
 * and dlclose.
 */
void *PREFIX(dlopen)(char *filename, int flag);

/**
 * Unloads the specified library.
 *
 * @param handle handle (as returned by dlopen) of the library to close.
 *
 * @return zero, if success, non-zero otherwise.
 */
int PREFIX(dlclose)(void *handle);

#endif /* DL_H */
