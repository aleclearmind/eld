// OR1K uses reloc with addend
#include <stdint.h>
#define ELF_USES_RELOCA
#include "elf.h"

// Things specific to our architecture

// TODO: detect automatically the following typedef
// e.g. #if __WORDSIZE == 64

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

#if defined(__or1k__)
#define ELF_ENDIANNESS ELFDATA2MSB
#define ENDIANNESS_NAME "big-endian"
#elif defined(__or1kle__)
#define ELF_ENDIANNESS ELFDATA2LSB
#define ENDIANNESS_NAME "little-endian"
#endif

// End of things specific to our architecture
