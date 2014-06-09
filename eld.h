#ifndef ELD_H
#define ELD_H

#include <sys/queue.h>
#include "elf-wrapper.h"

typedef unsigned char mem_t;

// Linker generated symbols
extern Elf_Dyn _DYNAMIC;

typedef union {
  Elf_Word d_val;
  Elf_Addr d_ptr;
} Elf_DynValue;

typedef struct {
  Elf_DynValue basic[DT_NUM];
  Elf_Word relative_reloc_count;
  Elf_Word hash_nbuckets;
  Elf_Word *hash_buckets;
  Elf_Word hash_nchains;
  Elf_Word *hash_chains;
} dynamic_info_t;

typedef struct elf_object {
  mem_t *file_address;
  mem_t *load_address;
  // elf_offset = lib_buffer - min_address
  // Add this to addresses in the ELF file
  mem_t *elf_offset;

  char *soname;
  Elf_Dyn *dynamic_info_section;
  char *strtab;
  Elf_Sym *symtab;

  dynamic_info_t dynamic_info;
  SLIST_ENTRY(elf_object) next;
} elf_object_t;

typedef SLIST_HEAD(elf_object_list_head, elf_object) elf_object_list_head_t;
extern elf_object_list_head_t elves;

/**
 * Check if the specified ELF object descriptor is registered.
 *
 * @param this the input ELF object descriptor.
 *
 * @return zero, if success, non-zero otherwise.
 */
int eld_elf_object_is_registered(elf_object_t *this);

/**
 * Find a symbol just using its name.
 *
 * @param this the input ELF object descriptor.
 * @param name symbol name to search.
 * @param match [out] pointer where the matching symbol will be stored.
 * @param match_elf [out] pointer to where the matching ELF symbol
 *
 * @return zero, if success, non-zero otherwise.
 */
int eld_elf_object_find_symbol_by_name(elf_object_t *this, char *name,
				       Elf_Sym **match,
				       elf_object_t **match_elf);

/**
 * Remove it from the list of loaded objects and close it.
 *
 * @param this the input ELF object descriptor.
 *
 * @return zero, if success, non-zero otherwise.
 */
int eld_elf_object_close(elf_object_t *this);

/**
 * Create a new instance of an ELF object descriptor.
 *
 * @param soname the soname of the library.
 * @param length size of the library.
 *
 * @return a pointer to the ELF descriptor.
 */
elf_object_t * eld_elf_object_new(char *soname, int length);

/**
 * Handle the dynamic section of the ELF input object.
 *
 * @param this the input ELF object descriptor.
 *
 * @return zero, if success, non-zero otherwise.
 */
int eld_elf_object_handle_dyn(elf_object_t *this);

/**
 * Destructor for an ELF object descriptor. Calls the finalization
 * function and deallocates the associated memory.
 *
 * @param this the input ELF object descriptor.
 */
void eld_elf_object_destroy(elf_object_t *this);

/**
 * Check that the input ELF is appropriate for being loaded.
 *
 * @param this the input ELF object descriptor.
 *
 * @return zero, if success, non-zero otherwise.
 */
int eld_elf_object_check(elf_object_t *this);

/**
 * Load the ELF object in memory and initialize it.
 *
 * @param this the input ELF object descriptor.
 *
 * @return zero, if success, non-zero otherwise.
 */
int eld_elf_object_load(elf_object_t *this);

/**
 * Load a library already in memory.
 *
 * @param library pointer to the current position of the ELF file.
 * @param library_descriptor pointer where a pointer the newly allocated library
 * descriptor will be stored.
 *
 * @return zero, if success, non-zero otherwise.
 */
int eld_open(mem_t *library, elf_object_t **library_descriptor);

/**
 * Initialize ELF object list
 *
 * @return zero, if success, non-zero otherwise.
 */
__attribute__((constructor)) int eld_init();

/**
 * Cleanup ELF object list
 *
 * @return zero, if success, non-zero otherwise.
 */
__attribute__((destructor)) int eld_finish();

#endif /* ELD_H */
