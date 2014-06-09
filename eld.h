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

int eld_elf_object_is_registered(elf_object_t *this);
int eld_elf_object_find_symbol_by_name(elf_object_t *this, char *name,
				       Elf_Sym **match,
				       elf_object_t **match_elf);
int eld_elf_object_close(elf_object_t *this);
elf_object_t * eld_elf_object_new(char *soname, int length);
int eld_elf_object_handle_dyn(elf_object_t *this);
void eld_elf_object_destroy(elf_object_t *this);
int eld_elf_object_check(elf_object_t *this);
int eld_elf_object_load(elf_object_t *this);

int eld_open(mem_t *library, elf_object_t **library_descriptor);

__attribute__((constructor)) int eld_init();
__attribute__((destructor)) int eld_finish();
