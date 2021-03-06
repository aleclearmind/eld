#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "eld.h"
#include "support.h"

typedef unsigned long elf_hash_t;
typedef void (*t_init_function)(void);
typedef void (*t_fini_function)(void);
typedef Elf_Addr Elf_Addr_Unaligned __attribute__((aligned(1)));

/**
 * ELF hash function for quick symbol lookup
 *
 * @param cursor the name of the symbol to hash.
 *
 * @return the hash of the input symbol name.
 */
static elf_hash_t eld_elf_hash(char *cursor) {
  elf_hash_t result = 0;
  while (*cursor) {
    elf_hash_t tmp;
    result = (result << 4) + *cursor++;
    if ((tmp = result & 0xf0000000))
      result ^= tmp >> 24;
    result &= ~tmp;
  }
  return result;
}

elf_object_t * eld_elf_object_new(char *soname, int length) {
  elf_object_t *new_elf;
  new_elf = calloc(sizeof (char), sizeof (elf_object_t));

  if (!new_elf) return NULL;
  new_elf->soname = soname;

  return new_elf;
}

void eld_elf_object_destroy(elf_object_t *this) {
  if (!this) return;

  // Call the finalization function of the shared object
  t_fini_function fini_function =
    (t_fini_function) this->dynamic_info.basic[DT_FINI].d_ptr;
  if (fini_function && this->dynamic_info_section != &_DYNAMIC) {
    DBG_MSG("Calling fini_function(): %p", fini_function);
    fini_function();
    DBG_MSG("fini_function called");

    // Free the allocated memory
    free(this->load_address);
  }

  free(this);
}

/**
 * Get the symbol matching a specified name.
 *
 * @param this the input ELF object descriptor.
 * @param target_name symbol name.
 * @param target_hash hash of the symbol name.
 * @param target_symbol [out] pointer where the matching symbol will be stored.
 * @param weak_symbol [out] pointer where a weak matching symbol will be stored.
 * @param weak_elf [out] pointer to where a weak matching ELF will be stored.
 *
 * @return zero, if success, non-zero otherwise.
 */
static int eld_elf_object_get_symbol(elf_object_t *this, char *target_name,
                                     elf_hash_t target_hash,
                                     Elf_Sym **target_symbol,
                                     Elf_Sym **weak_symbol,
                                     elf_object_t **weak_elf) {
  CHECK_ARGS(this && target_name && target_symbol && weak_symbol && weak_elf &&
             this->dynamic_info.hash_buckets && this->dynamic_info.hash_chains);
  // TODO: lookup cache
  // TOOD: gnu hash

  Elf_Word item = this->dynamic_info.hash_buckets[target_hash %
          this->dynamic_info.hash_nbuckets];
  for (; item != STN_UNDEF; item = this->dynamic_info.hash_chains[item]) {
    Elf_Sym *symbol = this->symtab + item;

    if ((!symbol->st_value) ||
        (ELF_ST_TYPE(symbol->st_info) != STT_NOTYPE &&
         ELF_ST_TYPE(symbol->st_info) != STT_OBJECT &&
         ELF_ST_TYPE(symbol->st_info) != STT_FUNC)) {
      continue;
    }

    char *symbol_name = this->strtab + symbol->st_name;

    // Not sure about the first part of the check, *target_symbol should be NULL
    // in input
    if (symbol != *target_symbol && strcmp(symbol_name, target_name)) {
      continue;
    }

    // TODO: implement flags
    /*
    if (symbol->st_shndx == SHN_UNDEF) {
      if ((flags & SYM_PLT) || symbol->st_value == 0 ||
          ELF_ST_TYPE(symbol->st_info) != STT_FUNC)
        continue;
    }
     */

    if (ELF_ST_BIND(symbol->st_info) == STB_GLOBAL) {
      *target_symbol = symbol;
      return SUCCESS;
    } else if (ELF_ST_BIND(symbol->st_info) == STB_WEAK) {
      //
      if (!*weak_symbol) {
        *weak_symbol = symbol;
        *weak_elf = this;
        return ERROR_WEAK_RESULT;
      }
    }

  }

  return ERROR_SYMBOL_NOT_FOUND;
}

/**
 * Look for a symbol in the specified ELF or in one of those it is
 * depending on.
 *
 * @param this the input ELF object descriptor.
 * @param name symbol name to search.
 * @param hash hash of the symbol name.
 * @param match [out] pointer where the matching symbol will be stored.
 * @param match_elf [out] pointer to where the matching ELF symbol
 * will be stored.
 *
 * @return zero, if success, non-zero otherwise.
 */
static int eld_elf_object_find_symbol(elf_object_t *this, char *name,
                                      elf_hash_t hash,
                                      Elf_Sym **match,
                                      elf_object_t **match_elf) {
  CHECK_ARGS(name && match && match_elf);

  // TODO: implement full search in the right order
  // This is a simplified search order, first in the current library, then in
  // all the others in load order

  Elf_Sym *weak_match = NULL;
  elf_object_t *weak_match_elf = NULL;
  int result = ERROR_SYMBOL_NOT_FOUND;

  if (this) {
    DBG_MSG("Looking for symbol \"%s\" in the library \"%s\" itself", name,
          this->soname);
    if ((result =
	 eld_elf_object_get_symbol(this, name, hash, match,
				   &weak_match, &weak_match_elf)) == SUCCESS) {

      // TODO: is the following correct?
      *match_elf = this;
      DBG_MSG("Symbol \"%s\" found in the library \"%s\" itself", name,
	      this->soname);
    } else if (result != ERROR_SYMBOL_NOT_FOUND && result != ERROR_WEAK_RESULT) {
      return result;
    }
  }

  // Look in all the other elves
  elf_object_t *loaded_elf = NULL;

  SLIST_FOREACH(loaded_elf, &elves, next) {
    // Don't check again the suggested ELF
    if (loaded_elf == this) continue;

    DBG_MSG("Looking for symbol \"%s\" in the \"%s\" library", name,
	    loaded_elf->soname);
    if ((result = eld_elf_object_get_symbol(loaded_elf, name, hash, match,
					    &weak_match,
					    &weak_match_elf)) == SUCCESS) {
      *match_elf = loaded_elf;
      DBG_MSG("Symbol \"%s\" found in the \"%s\" library", name,
	      loaded_elf->soname);
      break;
    } else if (result != ERROR_SYMBOL_NOT_FOUND &&
	       result != ERROR_WEAK_RESULT) {
      return result;
    }
  }

  if (!*match && weak_match) {
    DBG_MSG("Symbol \"%s\" has a weak match in \"%s\" library", name,
            weak_match_elf->soname);
    *match = weak_match;
    *match_elf = weak_match_elf;
  }

  if (!match) DBG_MSG("Symbol \"%s\" not found", name);

  return match ? SUCCESS : ERROR_SYMBOL_NOT_FOUND;
}

int eld_elf_object_find_symbol_by_name(elf_object_t *this, char *name,
				       Elf_Sym **match,
				       elf_object_t **match_elf) {
  return eld_elf_object_find_symbol(this, name, eld_elf_hash(name), match,
				    match_elf);
}

/**
 * Relocate symbols listed in an ELF section.
 *
 * @param this the input ELF object descriptor.
 * @param reloc_index index of the relocation section.
 * @param reloc_size_index size of the relocation section.
 *
 * @return zero, if success, non-zero otherwise.
 */
static int eld_elf_object_relocate(elf_object_t *this,
                                   int reloc_index, int reloc_size_index) {
  CHECK_ARGS(this);
  int result = SUCCESS;

  // We only support relocation with addend
  int reloc_count =
          this->dynamic_info.basic[reloc_size_index].d_val / sizeof (Elf_Rela);
  int relative_reloc_count = (reloc_index == DT_RELATIVE_RELOC) ?
          this->dynamic_info.relative_reloc_count : 0;
  Elf_Rela *first_reloc =
          (Elf_Rela *) this->dynamic_info.basic[reloc_index].d_ptr;

  DBG_MSG("Relocating section %d (size: %d)", reloc_index, reloc_count);

  int i = 0;
  Elf_Rela *reloc = first_reloc;
  Elf_Addr *patch_location = NULL;

  for (; i < relative_reloc_count && i < reloc_count; reloc++, i++) {
#ifndef NDEBUG
    if (ELF_R_TYPE(reloc->r_info) != R_OR1K_RELATIVE) {
      DBG_MSG("The %dth relocation is not relative, while the first %d should.",
              i, relative_reloc_count);
      return ERROR_GENERIC;
    }
#endif
    patch_location = (Elf_Addr *) (reloc->r_offset + this->elf_offset);
    *patch_location += (uintptr_t) this->elf_offset;
  }

  // Continue from the index left from the previous loop
  for (; i < reloc_count; reloc++, i++) {
    int type = ELF_R_TYPE(reloc->r_info);
    Elf_Sym *symbol = &this->symtab[ELF_R_SYM(reloc->r_info)];

    Elf_Sym *match = NULL;
    elf_object_t *match_elf = NULL;
    patch_location = (Elf_Addr *) (reloc->r_offset + this->elf_offset);

    // TODO: check also if it's local
    if (symbol->st_name != 0) {
      char *name = this->strtab + symbol->st_name;

      // Compute the hash
      elf_hash_t hash = eld_elf_hash(name);

      // Look for the symbol
      RETURN_ON_ERROR(eld_elf_object_find_symbol(this, name, hash, &match,
						 &match_elf));
    } else {
      match = symbol;
      match_elf = this;
    }

    Elf_Addr symbol_address = (Elf_Addr) (match_elf->relocation_load_address +
                                          match->st_value);
    int32_t relative_address;

    switch (type) {
      case R_OR1K_NONE:
        break;

      case R_OR1K_32:
        // Support relocations on misaligned offsets
        *((Elf_Addr_Unaligned *) patch_location) = symbol_address +
                reloc->r_addend;
        break;

      case R_OR1K_INSN_REL_26:
        relative_address = symbol_address +
          reloc->r_addend - ((uint32_t) patch_location);

        if (relative_address >= (1 << 27) || relative_address < -(1 << 27)) {
          DBG_MSG("Relocation too far away: "
                  "from %p to 0x%" PRIu32 " (%" PRIi32 ").",
                  patch_location,
                  (uint32_t) symbol_address + reloc->r_addend,
                  (int32_t) relative_address);
          return ERROR_RELOCATION_TOO_FAR;
        }

        relative_address >>= 2;
        *patch_location &= ~((1 << 26) - 1);
        *patch_location |= relative_address & ((1 << 26) - 1);
        break;

      case R_OR1K_LO_16_IN_INSN:
        *patch_location &= 0xffff0000;
        *patch_location |= (symbol_address + reloc->r_addend) & 0x0000ffff;
        break;

      case R_OR1K_HI_16_IN_INSN:
        *patch_location &= 0xffff0000;
        *patch_location |= ((uint32_t) (symbol_address + reloc->r_addend)) >> 16;
        break;

      case R_OR1K_GLOB_DAT:
      case R_OR1K_JMP_SLOT:
        *patch_location = symbol_address + reloc->r_addend;
        break;

      case R_OR1K_COPY:
        if (symbol_address) {
          memcpy(patch_location, (void *) symbol_address, match->st_size);
        }
        break;

      default:
        return ERROR_UNKNOWN_RELOCATION_TYPE;
    }

  }

  return SUCCESS;
}

int eld_elf_object_check(elf_object_t *this) {
  CHECK_ARGS(this && this->file_address);

  Elf_Ehdr *elf_header = (Elf_Ehdr *) this->file_address;

  if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
      elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
      elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
      elf_header->e_ident[EI_MAG3] != ELFMAG3 ||
      elf_header->e_type != ET_DYN ||
      elf_header->e_machine != EM_OPENRISC ||
      elf_header->e_ident[EI_DATA] != ELF_ENDIANNESS) {

    DBG_MSG("Not an OpenRISC " ENDIANNESS_NAME " ELF dynamic shared object.");
    return ERROR_UNEXPECTED_FORMAT;
  }

  return SUCCESS;
}

/**
 * Allocates a memory area of the specified size to hold the ELF object and
 * stores its address in this->load_address. Additionally, for greater
 * flexibility, it also stores in this->relocation_load_address the value to use
 * as the base address of the library while applying relocations. This function
 * is defined as weak, feel free to provide your own implementation.
 *
 * @param this the input ELF object descriptor.
 * @param size size, in bytes, to allocate.
 *
 * @return zero, if success, non-zero otherwise.
 */
__attribute__ ((weak))
int eld_elf_object_allocate(elf_object_t *this, size_t size) {

  this->load_address = malloc(size);
  this->relocation_load_address = this->load_address;

  if (!this->load_address || !this->relocation_load_address) {
    DBG_MSG("Cannot allocate the necessary memory (0x%x bytes)",
	    (unsigned int) size);
    return ERROR_OUT_OF_MEMORY;
  }

  return SUCCESS;
}

int eld_elf_object_load(elf_object_t *this) {
  CHECK_ARGS(this && this->file_address);

  int result = SUCCESS;

  Elf_Ehdr *elf_header = (Elf_Ehdr *) this->file_address;
  Elf_Phdr *program_header_begin =
          (Elf_Phdr *) (this->file_address + elf_header->e_phoff);
  Elf_Phdr *program_header_end = program_header_begin + elf_header->e_phnum;
  Elf_Addr min_address = 0, max_address = 0;
  this->dynamic_info_section = NULL;

  for (Elf_Phdr *program_header = program_header_begin;
       program_header < program_header_end; program_header++) {
    switch (program_header->p_type) {
      case PT_LOAD:
        if (program_header->p_vaddr < min_address) {
          min_address = program_header->p_vaddr;
        }
        if (program_header->p_vaddr + program_header->p_memsz > max_address) {
          max_address = program_header->p_vaddr + program_header->p_memsz;
        }
        break;

      case PT_DYNAMIC:
        this->dynamic_info_section = (Elf_Dyn *) program_header->p_vaddr;
        break;

      default:
        // Ignore
        break;
    }
  }

  if (!max_address) {
    DBG_MSG("There's nothing to load in the ELF");
    return ERROR_GENERIC;
  }

  Elf_MemSz to_allocate = max_address - min_address;
  RETURN_ON_ERROR(eld_elf_object_allocate(this, to_allocate));

  DBG_MSG("The library has been loaded at %p, "
      "relocations will be relative to %p", this->load_address,
       this->relocation_load_address);

  this->elf_offset = this->load_address - min_address;

  // Load from file
  for (Elf_Phdr *program_header = program_header_begin;
       program_header < program_header_end; program_header++) {
    if (program_header->p_type == PT_LOAD) {
      // Do we have something to take from the file?
      if (program_header->p_filesz > 0) {
        memcpy(this->elf_offset + program_header->p_vaddr,
               this->file_address + program_header->p_offset,
               program_header->p_filesz);
      }

      // If there's nothing to take from the file or in any case less than
      // what must be in memory, zero-fill
      if (program_header->p_filesz < program_header->p_memsz) {

        memset(this->elf_offset + program_header->p_vaddr +
               program_header->p_filesz,
               0, program_header->p_memsz - program_header->p_filesz);
      }
    }
  }

  // Update pointers
  this->dynamic_info_section = (Elf_Dyn *) (this->elf_offset +
                                            (Elf_Addr) this->dynamic_info_section);

  return SUCCESS;
}

int eld_elf_object_handle_dyn(elf_object_t *this) {
  CHECK_ARGS(this && this->dynamic_info_section);

  int result = SUCCESS;

  // First pass over the dynamic entries
  for (Elf_Dyn *dynamic_info_entry = this->dynamic_info_section;
       dynamic_info_entry->d_tag != DT_NULL;
       dynamic_info_entry++) {

    // Store in an array (< DT_NUM) or structure
    if (dynamic_info_entry->d_tag < DT_NUM) {
      this->dynamic_info.basic[dynamic_info_entry->d_tag].d_ptr =
              dynamic_info_entry->d_un.d_ptr;
    } else if (dynamic_info_entry->d_tag == DT_RELATIVE_RELOC_COUNT) {
      this->dynamic_info.relative_reloc_count = dynamic_info_entry->d_un.d_val;
    }
  }

  // These entries are addresses and therefore require relocation
  int to_rebase[] = {DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA,
                     DT_REL, DT_INIT, DT_FINI, DT_JMPREL};

  for (unsigned int counter = 0;
       counter < sizeof (to_rebase) / sizeof (int); counter++) {
    if (this->dynamic_info.basic[to_rebase[counter]].d_ptr) {
      this->dynamic_info.basic[to_rebase[counter]].d_ptr +=
              (Elf_Addr) this->elf_offset;
    }
  }

  this->strtab = (char *) this->dynamic_info.basic[DT_STRTAB].d_ptr;
  this->symtab = (Elf_Sym *) this->dynamic_info.basic[DT_SYMTAB].d_ptr;

  // Lookups in the string table
  if (this->dynamic_info.basic[DT_SONAME].d_ptr) {
    this->dynamic_info.basic[DT_SONAME].d_ptr += (Elf_Addr) this->strtab;
    this->soname = (char *) this->dynamic_info.basic[DT_SONAME].d_ptr;
    DBG_MSG("Loading \"%s\"", (char *) this->soname);
  }

  if (this->dynamic_info.basic[DT_RPATH].d_ptr) {
    this->dynamic_info.basic[DT_RPATH].d_ptr += (Elf_Addr) this->strtab;
  }

  // Look for dependencies
  for (Elf_Dyn *dynamic_info_entry = this->dynamic_info_section;
       dynamic_info_entry->d_tag != DT_NULL;
       dynamic_info_entry++) {

    // If there's a dependency
    if (dynamic_info_entry->d_tag == DT_NEEDED &&
        dynamic_info_entry->d_un.d_ptr) {

      int lib_found = 0;

      // Take the name of the library from the string table
      char *needed_lib_name = this->strtab + dynamic_info_entry->d_un.d_ptr;

      // Look for the library in the already loaded ELVes
      elf_object_t *loaded_elf = NULL;

      SLIST_FOREACH(loaded_elf, &elves, next) {
        if (loaded_elf->soname &&
            strncmp(loaded_elf->soname, needed_lib_name, 1024) == 0) {
          lib_found = 1;
          break;
        }
      }

      if (!lib_found) {
        DBG_MSG("Library %s has not been loaded", needed_lib_name);
        return ERROR_LIB_NOT_FOUND;
      }
    }
  }

  if (this->dynamic_info.basic[DT_HASH].d_ptr) {

    Elf_Word *hashtab = (Elf_Word *) this->dynamic_info.basic[DT_HASH].d_ptr;
    this->dynamic_info.hash_nbuckets = hashtab[0];
    this->dynamic_info.hash_nchains = hashtab[1];
    this->dynamic_info.hash_buckets = hashtab + 2;
    this->dynamic_info.hash_chains = this->dynamic_info.hash_buckets +
            this->dynamic_info.hash_nbuckets;
  }

  // TODO: handle errors
  RETURN_ON_ERROR(eld_elf_object_relocate(this, DT_REL, DT_RELSZ));
  RETURN_ON_ERROR(eld_elf_object_relocate(this, DT_RELA, DT_RELASZ));
  // TODO: implement lazy loading (see _dl_md_reloc_got)
  RETURN_ON_ERROR(eld_elf_object_relocate(this, DT_JMPREL, DT_PLTRELSZ));

  t_init_function init_function =
          (t_init_function) this->dynamic_info.basic[DT_INIT].d_ptr;

  if (init_function && this->dynamic_info_section != &_DYNAMIC) {
    DBG_MSG("Calling init_function(): %p", init_function);
    init_function();
    DBG_MSG("init_function called");
  }

  return SUCCESS;
}

int eld_elf_object_is_registered(elf_object_t *this) {
  elf_object_t *loaded_elf = NULL;
  SLIST_FOREACH(loaded_elf, &elves, next) {
    if (loaded_elf == this) return SUCCESS;
  }
  return ERROR_LIB_NOT_FOUND;
}

int eld_elf_object_close(elf_object_t *this) {
  CHECK_ARGS(this);

  int result = SUCCESS;

  RETURN_ON_ERROR(eld_elf_object_is_registered(this));

  SLIST_REMOVE(&elves, this, elf_object, next);
  eld_elf_object_destroy(this);

  return SUCCESS;
}
