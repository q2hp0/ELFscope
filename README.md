# ELFscope

A small command line tool for looking inside Linux ELF files. It parses the
file itself (no readelf/objdump behind the scenes) and never executes the
thing it analyzes.

## What it does

- ELF header, section table, program headers, section-to-segment mapping
- dynamic section metadata, dynamic relocations, symbol tables, DT_NEEDED libs
- hardening report: PIE, NX stack, RELRO, stack canary, FORTIFY, RPATH/RUNPATH,
  text relocations, W+X segments
- statistics from the section, symbol and dependency analyzers
- comparison of two ELF files
- damaged input ends in a normal error message, not a crash

## Build

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Needs a C++20 compiler and CMake 3.20+. Useful options:

| option | meaning |
| --- | --- |
| `-DELFSCOPE_SANITIZE=ON` | build with ASan + UBSan (use with `-DCMAKE_BUILD_TYPE=Debug`) |
| `-DELFSCOPE_WERROR=ON` | warnings become errors |

## Usage

```text
elfscope [options] <command> <file>
elfscope [options] compare <file-a> <file-b>
```

| command | output |
| --- | --- |
| `info` | ELF header summary |
| `sections` | section header table |
| `segments` | program header table |
| `mapping` | which section lives in which segment |
| `dynamic` | dynamic section metadata |
| `relocations` | dynamic relocations |
| `symbols` | symbol tables |
| `dependencies` | needed libraries |
| `security` | hardening checks and findings |
| `stats` | analyzer numbers |
| `compare` | differences between two files |
| `all` | everything except compare |

Options: `-v/--verbose`, `-V/--version`, `-h/--help`.
Exit codes: `0` ok, `1` the file could not be analyzed, `2` bad command line.

### Example

```text
$ elfscope security ./a.out
security: ./a.out
  kind: position independent executable
  linking: dynamic
  PIE: yes
  NX stack: yes
  RELRO: full
  stack canary: yes
  fortify: yes (2 fortified functions)
  stripped: no
  ...
no findings
```

## Limits

- only little endian ELF files are parsed for now
- relocations are the dynamic ones (`.rela.dyn`, `.rela.plt`), not the
  `.rela.text` style sections of object files
- canary and FORTIFY detection is symbol based, so a fully stripped static
  binary can hide them

## Layout

```text
include/elfscope   public headers
src/parser         ELF structure readers
src/analysis       analyzers (sections, symbols, dependencies, security, compare)
src/cli            argument parsing, commands, output formatting
src/utils          bounded file access, logging
tests              unit tests, fixtures are built from examples/sample.c
docs               format notes, architecture, usage
```

MIT licensed.
