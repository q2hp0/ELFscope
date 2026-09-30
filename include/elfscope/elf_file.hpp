#pragma once

#include <cstdint>
#include <string>

namespace elfscope {

enum class ElfClass {
    elf32,
    elf64,
    unknown
};

enum class Endianness {
    little,
    big,
    unknown
};

struct ElfFile {
    std::string path;
    ElfClass elf_class = ElfClass::unknown;
    Endianness endianness = Endianness::unknown;
    std::uint8_t os_abi = 0;
    std::uint16_t type = 0;
    std::uint16_t machine = 0;
    std::uint64_t entry = 0;
    std::uint64_t program_header_offset = 0;
    std::uint64_t section_header_offset = 0;
    std::uint16_t program_header_count = 0;
    std::uint16_t section_header_count = 0;
    std::uint16_t section_name_index = 0;
    std::string interpreter;
};

}
