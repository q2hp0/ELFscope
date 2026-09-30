# ELF Format

ELFscope analyzes Executable and Linkable Format files used by Linux and other Unix-like systems.

## Core structures

An ELF file contains:

- ELF header
- Program header table
- Section header table
- Sections
- Optional dynamic linking information
- Optional symbol tables
- Optional relocation tables

## ELF header

The ELF header identifies:

- ELF32 or ELF64
- byte order
- OS ABI
- object type
- target machine
- entry point
- program header location
- section header location

## Program headers

Program headers describe runtime loading information.

Important segment types include:

- PT_LOAD
- PT_DYNAMIC
- PT_INTERP
- PT_NOTE
- PT_GNU_STACK
- PT_GNU_RELRO

## Sections

Common sections include:

- .text
- .rodata
- .data
- .bss
- .dynsym
- .dynstr
- .dynamic
- .rela.dyn
- .rela.plt

## Dynamic linking

The dynamic section contains metadata used by the runtime loader.

ELFscope extracts dependencies, search paths, relocation metadata, initialization metadata, and dynamic flags.

## Relocations

Relocations describe address fixups performed by the linker or dynamic loader.

Common x86-64 relocation types include:

- R_X86_64_RELATIVE
- R_X86_64_GLOB_DAT
- R_X86_64_JUMP_SLOT
- R_X86_64_DTPMOD64
- R_X86_64_TPOFF64
