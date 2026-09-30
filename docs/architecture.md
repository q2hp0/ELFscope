# ELFscope Architecture

ELFscope is organized into parser, analysis, utility, and CLI layers.

## Parser

The parser layer reads ELF structures without executing the analyzed file.

Components include:

- ELF header parser
- section reader
- symbol reader
- program header reader
- interpreter reader
- dynamic reader
- dynamic metadata reader
- relocation reader

## Analysis

The analysis layer operates on parsed ELF structures.

Current components include:

- section statistics
- symbol statistics
- dependency normalization
- section-to-segment mapping
- file comparison
- relocation analysis
- security / hardening checks

## Utilities

Utility components provide:

- bounded file access
- logging
- common error types

## CLI

The command layer handles command parsing and presentation.

The intended command set is:

```text
elfscope info <file>
elfscope sections <file>
elfscope segments <file>
elfscope mapping <file>
elfscope dynamic <file>
elfscope relocations <file>
elfscope symbols <file>
elfscope dependencies <file>
elfscope security <file>
elfscope stats <file>
elfscope compare <file-a> <file-b>
elfscope all <file>
```

## Design goals

ELFscope should parse ELF files directly instead of shelling out to readelf or objdump.

Malformed input must result in controlled errors rather than out-of-bounds reads or undefined behavior.

Analysis code should operate on parsed structures instead of duplicating binary parsing whenever possible.
