#include "support.h"
#include "eld.h"

/* Some macro to add support for prefixing dl* functions */
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
void *PREFIX(dlsym)(void *handle, char *symbol) {
  CHECK_ARGS_RET(symbol, 0);

  DBG_MSG("dlsym(%p, %s)", handle, symbol);
  if (handle) RETURN_NULL_ON_ERROR(eld_elf_object_is_registered(handle));

  Elf_Sym *match = NULL;
  elf_object_t *match_elf = NULL;

  RETURN_NULL_ON_ERROR(eld_elf_object_find_symbol_by_name(handle, symbol,
							  &match, &match_elf));

  return match_elf->elf_offset + match->st_value;
}

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
void *PREFIX(dlopen)(char *filename, int flag) {
  DBG_MSG("dlopen(%p, %x)", filename, flag);
  CHECK_ARGS_RET(filename, NULL);

  // TODO: flags
  mem_t *library = (unsigned char *) filename;

  elf_object_t *loaded_elf = NULL;
  SLIST_FOREACH(loaded_elf, &elves, next) {
    if (loaded_elf->file_address == library) {
      DBG_MSG("File at %p already registered as \"%s\"", filename,
	      loaded_elf->soname);
      return NULL;
    }
  }

  elf_object_t *library_descriptor = NULL;

  RETURN_NULL_ON_ERROR(eld_open(library, &library_descriptor));
  // TODO: implement dlerror

  return library_descriptor;
}

/**
 * Unloads the specified library.
 *
 * @param handle handle (as returned by dlopen) of the library to close.
 *
 * @return zero, if success, non-zero otherwise.
 */
int PREFIX(dlclose)(void *handle) {
  CHECK_ARGS(handle);
  int result = SUCCESS;

  RETURN_ON_ERROR(eld_elf_object_is_registered(handle));

  return eld_elf_object_close(handle);
}
