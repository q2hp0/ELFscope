#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"

#include <elf.h>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace elfscope {

void ElfParser::check_magic(const unsigned char* ident, const std::string& path)
{
    if (ident[EI_MAG0] != ELFMAG0 ||
        ident[EI_MAG1] != ELFMAG1 ||
        ident[EI_MAG2] != ELFMAG2 ||
        ident[EI_MAG3] != ELFMAG3) {
        throw FormatError("not an elf file: " + path);
    }
}

ElfFile ElfParser::parse(const std::string& path) const
{
    std::ifstream file(path, std::ios::binary);

    if (!file) {
        throw FileError("can't open file: " + path);
    }

    unsigned char ident[EI_NIDENT]{};

    file.read(reinterpret_cast<char*>(ident), EI_NIDENT);

    if (file.gcount() != EI_NIDENT) {
        throw FormatError("file is too small: " + path);
    }

    check_magic(ident, path);

    ElfFile result;
    result.path = path;
    result.os_abi = ident[EI_OSABI];

    if (ident[EI_CLASS] == ELFCLASS32) {
        result.elf_class = ElfClass::elf32;
    } else if (ident[EI_CLASS] == ELFCLASS64) {
        result.elf_class = ElfClass::elf64;
    } else {
        throw FormatError("unsupported elf class: " + path);
    }

    if (ident[EI_DATA] == ELFDATA2LSB) {
        result.endianness = Endianness::little;
    } else if (ident[EI_DATA] == ELFDATA2MSB) {
        result.endianness = Endianness::big;
    } else {
        throw FormatError("unknown elf byte order: " + path);
    }

    if (result.endianness != Endianness::little) {
        throw FormatError("big endian elf files are not supported yet");
    }

    file.seekg(0);

    if (result.elf_class == ElfClass::elf64) {
        Elf64_Ehdr header{};

        file.read(reinterpret_cast<char*>(&header), sizeof(header));

        if (!file) {
            throw FormatError("failed to read elf64 header: " + path);
        }

        result.type = header.e_type;
        result.machine = header.e_machine;
        result.entry = header.e_entry;
        result.program_header_offset = header.e_phoff;
        result.section_header_offset = header.e_shoff;
        result.program_header_count = header.e_phnum;
        result.section_header_count = header.e_shnum;
        result.section_name_index = header.e_shstrndx;
    } else {
        Elf32_Ehdr header{};

        file.read(reinterpret_cast<char*>(&header), sizeof(header));

        if (!file) {
            throw FormatError("failed to read elf32 header: " + path);
        }

        result.type = header.e_type;
        result.machine = header.e_machine;
        result.entry = header.e_entry;
        result.program_header_offset = header.e_phoff;
        result.section_header_offset = header.e_shoff;
        result.program_header_count = header.e_phnum;
        result.section_header_count = header.e_shnum;
        result.section_name_index = header.e_shstrndx;
    }

    return result;
}

}
