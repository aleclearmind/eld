// TODO: declare we use addends in in symbol table
// TODO: copy sys/queue.h
// TODO: split me
// TODO: add support for having different address spaces
// TODO: test with non-function symbols
// TODO: call fini function
// TODO: TLS

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/queue.h>

#include "libmy.so.h"
#include "libyour.so.h"

// OR1K uses reloc with addend
#define ELF_USES_RELOCA
#include "elf.h"


// Error codes
// TODO: prefix with ELD_
#define SUCCESS 0
#define ERROR_GENERIC 1
#define ERROR_BAD_ARGS 2
#define ERROR_LIB_NOT_FOUND 3
#define ERROR_OUT_OF_MEMORY 4
#define ERROR_UNEXPECTED_FORMAT 5
#define ERROR_WEAK_RESULT 6
#define ERROR_SYMBOL_NOT_FOUND 7
#define ERROR_UNKNOWN_RELOCATION_TYPE 8

// Things specific to our architecture

// TODO: switch to ElfW($)?
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Word Elf_Word;
typedef Elf32_Rela Elf_Rela;
typedef Elf32_Sym Elf_Sym;
typedef uint32_t Elf_MemSz;
#define MAX_ADDR UINT32_MAX

#define DT_RELATIVE_RELOC DT_RELA
#define DT_RELATIVE_RELOC_COUNT DT_RELACOUNT

#define ELF_ST_BIND(val) ELF32_ST_BIND(val)
#define ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#define ELF_R_SYM(i)     ELF32_R_SYM(i)
#define ELF_R_TYPE(i)    ELF32_R_TYPE(i)

#ifndef ELF_CLASS
#define ELF_CLASS ELFCLASS32
#endif

// End of things specific to our architecture

typedef unsigned char mem_t;

// Proof that macros lead to bad stuffs
#define DBG_MSG(format, ...) printf("[%s:%d] " format "\n", __FILE__, __LINE__, \
    ##__VA_ARGS__ )
#define CHECK_ARGS_RET(condition, ret) \
  do { \
    if (!(condition)) { \
      DBG_MSG("Bad arguments."); \
      return (ret); \
    } \
  } while(0)
#define CHECK_ARGS(condition) CHECK_ARGS_RET(condition, ERROR_BAD_ARGS)


// Using this macro leads to loss of information on the error
#define RETURN_NULL_ON_ERROR(expression)  \
  do { \
    if ((expression) != SUCCESS) { \
      return NULL; \
    } \
  } while (0)

#define ON_ERROR(expression, action) \
  do { \
    if ((result = (expression)) != SUCCESS) { \
      action; \
    } \
  } while (0)
#define RETURN_ON_NULL(expression) \
  do { \
    if (!(expression)) return ERROR_GENERIC; \
  } while(0)

// Assumes a "result" variable has been declared
#define RETURN_ON_ERROR(expression) ON_ERROR(expression, return result)

// Also assumes in the function there's a "fail" label
#define FAIL_ON_ERROR(expression) ON_ERROR(expression, goto fail)

#define STR_PAR(str) (str), (sizeof(str))

typedef Elf_Addr Elf_Addr_Unaligned __attribute__((aligned(1)));
typedef void (*t_init_function)(void);
typedef void (*t_fini_function)(void);

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
elf_object_list_head_t elves;

typedef unsigned long elf_hash_t;

// Linker generated symbols
extern Elf_Dyn _DYNAMIC;

// Declarations
static int eld_elf_object_handle_dyn(elf_object_t *this);

elf_hash_t eld_elf_hash(char *cursor) {
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

/**
 * Add an ELF to the list
 * @param so_name
 * @param length
 * @return
 */
static elf_object_t * eld_elf_object_new(char *soname, int length) {
  elf_object_t *new_elf;
  new_elf = calloc(sizeof (char), sizeof (elf_object_t));

  if (!new_elf) return NULL;
  new_elf->soname = soname;

  return new_elf;
}

static void eld_elf_object_destroy(elf_object_t *this) {
  if (!this) return;

  if (this->dynamic_info_section != &_DYNAMIC) {
    free(this->load_address);
  }

  free(this);
}

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

/**
 *
 * @param dynamic_info
 * @param reloc_index
 * @param reloc_size_index
 * @param elf_offset
 * @return
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
    char *name = this->strtab + symbol->st_name;
    patch_location = (Elf_Addr *) (reloc->r_offset + this->elf_offset);

    // Compute the hash
    elf_hash_t hash = eld_elf_hash(name);

    // Look for the symbol
    Elf_Sym *match = NULL;
    elf_object_t *match_elf = NULL;

    RETURN_ON_ERROR(eld_elf_object_find_symbol(this, name, hash, &match,
                                               &match_elf));

    Elf_Addr symbol_address = (Elf_Addr) (match_elf->elf_offset + match->st_value);

    switch (type) {
      case R_OR1K_NONE:
        break;

      case R_OR1K_8:
      case R_OR1K_16:
      case R_OR1K_32:
        // Support relocations on misaligned offsets
        *((Elf_Addr_Unaligned *) patch_location) = symbol_address +
                reloc->r_addend;
        break;

      case R_OR1K_8_PCREL:
      case R_OR1K_16_PCREL:
      case R_OR1K_32_PCREL:
      case R_OR1K_INSN_REL_26:
        *patch_location = symbol_address + reloc->r_addend;
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

/**
 *
 * @param library
 * @return
 */
static int eld_elf_object_check(elf_object_t *this) {
  CHECK_ARGS(this && this->file_address);

  Elf_Ehdr *elf_header = (Elf_Ehdr *) this->file_address;

  if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
      elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
      elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
      elf_header->e_ident[EI_MAG3] != ELFMAG3 ||
      elf_header->e_type != ET_DYN ||
      elf_header->e_machine != EM_OPENRISC ||
      elf_header->e_ident[EI_DATA] != ELFDATA2MSB) {

    DBG_MSG("Not an OpenRISC big-endian ELF dynamic shared object.");
    return ERROR_UNEXPECTED_FORMAT;
  }

  return SUCCESS;
}

/**
 *
 * @param library OUT
 * @param dynamic_info_offset OUT
 * @param destination OUT
 * @param elf_offset OUT
 * @return
 */
static int eld_elf_object_load(elf_object_t *this) {
  CHECK_ARGS(this && this->file_address);

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
  this->load_address = malloc(to_allocate);

  if (!this->load_address) {
    DBG_MSG("Cannot allocate the necessary memory (0x%x bytes)",
	    (unsigned int) to_allocate);
    return ERROR_OUT_OF_MEMORY;
  } else {
    DBG_MSG("The library has been loaded at %p", this->load_address);
  }

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

/**
 *
 * @param dynamic_info_begin
 * @param elf_offset
 * @param dynamic_info
 * @param strtab OUT
 * @param symtab OUT
 * @return
 */
static int eld_elf_object_handle_dyn(elf_object_t *this) {
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

  // Create instance of elf_object_t
  int soname_len = 0;
  if (this->soname) {
    soname_len = strlen(this->soname);
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

  DBG_MSG("Calling init_function(): %p", init_function);
  if (init_function) init_function();
  DBG_MSG("init_function called");

  return SUCCESS;
}

static int eld_elf_object_is_registered(elf_object_t *this) {
  elf_object_t *loaded_elf = NULL;
  SLIST_FOREACH(loaded_elf, &elves, next) {
    if (loaded_elf == this) return SUCCESS;
  }
  return ERROR_LIB_NOT_FOUND;
}

static int eld_elf_object_close(elf_object_t *this) {
  CHECK_ARGS(this);

  SLIST_REMOVE(&elves, this, elf_object, next);
  eld_elf_object_destroy(this);

  return ERROR_LIB_NOT_FOUND;
}

/**
 * Load a library already in memory
 * @param library
 * @return
 */
static int eld_open(mem_t *library, elf_object_t **library_descriptor) {
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

void *dlsym(void *handle, char *symbol) {
  CHECK_ARGS_RET(symbol, 0);

  int result = SUCCESS;

  DBG_MSG("dlsym(%p, %s)", handle, symbol);
  if (handle) RETURN_NULL_ON_ERROR(eld_elf_object_is_registered(handle));

  Elf_Sym *match = NULL;
  elf_object_t *match_elf = NULL;

  RETURN_NULL_ON_ERROR(eld_elf_object_find_symbol(handle, symbol,
						  eld_elf_hash(symbol),
						  &match, &match_elf));

  return match_elf->elf_offset + match->st_value;
}

void *dlopen(mem_t *filename, int flag) {
  DBG_MSG("dlopen(%p, %x)", filename, flag);
  CHECK_ARGS_RET(filename, NULL);

  // TODO: flags
  int result = SUCCESS;
  mem_t *library = (unsigned char *) filename;

  elf_object_t *loaded_elf = NULL;
  SLIST_FOREACH(loaded_elf, &elves, next) {
    if (loaded_elf->file_address == filename) {
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

int main() {
  int result = SUCCESS;

  // Initialize the ELD library
  RETURN_ON_ERROR(eld_init());

  // Load libraries
  void *libyour_handle = NULL;
  RETURN_ON_NULL(libyour_handle = dlopen(libyour_so, 0));

  void *libmy_handle = NULL;
  RETURN_ON_NULL(libmy_handle = dlopen(libmy_so, 0));

  typedef int (*myfunc_ptr)();
  myfunc_ptr myfunc = NULL;
  myfunc = dlsym(NULL, "my");
  printf("%d\n", myfunc());

  // Close the loaded libraries
  RETURN_ON_ERROR(dlclose(libmy_handle));
  RETURN_ON_ERROR(dlclose(libyour_handle));

  // Finalize the ELD library
  RETURN_ON_ERROR(eld_finish());

  return result;
}
