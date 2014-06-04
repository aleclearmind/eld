#include "eld.h"
#include "support.h"

elf_object_list_head_t elves;

/**
 * Initialize ELF object list
 */
int eld_init() {
  int result = SUCCESS;
  DBG_MSG("Initializing ELD dynamic loader");

  SLIST_INIT(&elves);

  elf_object_t *main_elf = eld_elf_object_new(STR_PAR("main"));
  RETURN_ON_NULL(main_elf);
  main_elf->dynamic_info_section = &_DYNAMIC;
  RETURN_ON_ERROR(eld_elf_object_handle_dyn(main_elf));
  SLIST_INSERT_HEAD(&elves, main_elf, next);

  return SUCCESS;

}

/**
 * Cleanup ELF object list
 */
int eld_finish() {
  elf_object_t *elf = NULL;
  while (!SLIST_EMPTY(&elves)) {
    elf = SLIST_FIRST(&elves);
    SLIST_REMOVE_HEAD(&elves, next);
    eld_elf_object_destroy(elf);
  }

  return SUCCESS;
}

/**
 * Load a library already in memory
 * @param library
 * @return
 */
int eld_open(mem_t *library, elf_object_t **library_descriptor) {
  CHECK_ARGS(library && library_descriptor);

  int result = SUCCESS;
  elf_object_t *library_elf = eld_elf_object_new(NULL, 0);
  library_elf->file_address = library;

  FAIL_ON_ERROR(eld_elf_object_check(library_elf));

  FAIL_ON_ERROR(eld_elf_object_load(library_elf));

  if (library_elf->dynamic_info_section) {
    FAIL_ON_ERROR(eld_elf_object_handle_dyn(library_elf));
  } else {
    DBG_MSG("Not a dynamic library.");
    result = ERROR_UNEXPECTED_FORMAT;
    goto fail;
  }

  *library_descriptor = library_elf;
  SLIST_INSERT_HEAD(&elves, library_elf, next);

  DBG_MSG("%p correctly loaded: %s", library, library_elf->soname);
  return SUCCESS;

fail:
  if (library_elf) eld_elf_object_destroy(library_elf);
  return result;
}
