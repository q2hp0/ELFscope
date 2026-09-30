# Usage

Build ELFscope with CMake:

```bash
cmake -S . -B build
cmake --build build -j$(nproc)
```

Inspect an ELF header:

```bash
./build/elfscope info /bin/ls
```

Inspect sections:

```bash
./build/elfscope sections /bin/ls
```

Inspect program segments:

```bash
./build/elfscope segments /bin/ls
```

Inspect section-to-segment mapping:

```bash
./build/elfscope mapping /bin/ls
```

Inspect dynamic metadata:

```bash
./build/elfscope dynamic /bin/ls
```

Inspect relocations:

```bash
./build/elfscope relocations /bin/ls
```

Inspect symbols:

```bash
./build/elfscope symbols /bin/ls
```

Inspect dependencies:

```bash
./build/elfscope dependencies /bin/ls
```

Check the hardening of a binary:

```bash
./build/elfscope security /bin/ls
```

Show analyzer statistics:

```bash
./build/elfscope stats /bin/ls
```

Compare two ELF files:

```bash
./build/elfscope compare ./program-a ./program-b
```

Run the complete analysis:

```bash
./build/elfscope all /bin/ls
```

Options can go anywhere on the command line: `-v` logs progress, `-V` prints the
version, `-h` shows help. Exit codes are 0 (ok), 1 (file could not be analyzed)
and 2 (bad arguments).

The analyzed ELF file is never executed by ELFscope.
