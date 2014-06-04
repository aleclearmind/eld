#include "support.h"
#include "eld.h"

void *dlsym(void *handle, char *symbol) {
  CHECK_ARGS_RET(symbol, 0);

  DBG_MSG("dlsym(%p, %s)", handle, symbol);
  if (handle) RETURN_NULL_ON_ERROR(eld_elf_object_is_registered(handle));

  Elf_Sym *match = NULL;
  elf_object_t *match_elf = NULL;

  RETURN_NULL_ON_ERROR(eld_elf_object_find_symbol_by_name(handle, symbol,
							  &match, &match_elf));

  return match_elf->elf_offset + match->st_value;
}

void *dlopen(char *filename, int flag) {
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

int dlclose(void *handle) {
  CHECK_ARGS(handle);
  int result = SUCCESS;

  RETURN_ON_ERROR(eld_elf_object_is_registered(handle));

  return eld_elf_object_close(handle);
}
