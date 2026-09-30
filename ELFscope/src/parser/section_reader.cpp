#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"
#include "elfscope/string_table.hpp"

#include <elf.h>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace elfscope {

std::string section_type_name(std::uint32_t type)
{
    switch (type) {
    case SHT_NULL:
        return "NULL";
    case SHT_PROGBITS:
        return "PROGBITS";
    case SHT_SYMTAB:
        return "SYMTAB";
    case SHT_STRTAB:
        return "STRTAB";
    case SHT_RELA:
        return "RELA";
    case SHT_HASH:
        return "HASH";
    case SHT_DYNAMIC:
        return "DYNAMIC";
    case SHT_NOTE:
        return "NOTE";
    case SHT_NOBITS:
        return "NOBITS";
    case SHT_REL:
        return "REL";
    case SHT_SHLIB:
        return "SHLIB";
    case SHT_DYNSYM:
        return "DYNSYM";
    case SHT_INIT_ARRAY:
        return "INIT_ARRAY";
    case SHT_FINI_ARRAY:
        return "FINI_ARRAY";
    case SHT_GNU_HASH:
        return "GNU_HASH";
    case SHT_GNU_versym:
        return "GNU_VERSYM";
    case SHT_GNU_verneed:
        return "GNU_VERNEED";
    case SHT_GNU_verdef:
        return "GNU_VERDEF";
    default:
        return "UNKNOWN";
    }
}

std::string section_flags_name(std::uint64_t flags)
{
    std::string result;

    if (flags & SHF_WRITE) {
        result += 'W';
    }

    if (flags & SHF_ALLOC) {
        result += 'A';
    }

    if (flags & SHF_EXECINSTR) {
        result += 'X';
    }

    if (flags & SHF_MERGE) {
        result += 'M';
    }

    if (flags & SHF_STRINGS) {
        result += 'S';
    }

    if (flags & SHF_TLS) {
        result += 'T';
    }

    return result;
}

std::vector<Section> ElfParser::sections(const std::string& path) const
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file) {
        throw FileError("can't open file: " + path);
    }

    const auto file_size = static_cast<std::uint64_t>(file.tellg());

    if (file_size == 0) {
        throw FormatError("empty file: " + path);
    }

    ElfFile header = parse(path);
    std::vector<Section> result;

    if (header.section_header_count == 0) {
        return result;
    }

    if (header.section_header_offset >= file_size) {
        throw FormatError("section header table is outside the file");
    }

    if (header.elf_class == ElfClass::elf64) {
        const auto table_size =
            static_cast<std::uint64_t>(header.section_header_count) * sizeof(Elf64_Shdr);

        if (header.section_header_offset > file_size - table_size) {
            throw FormatError("section header table is truncated");
        }

        file.seekg(static_cast<std::streamoff>(header.section_header_offset));

        std::vector<Elf64_Shdr> raw(header.section_header_count);

        file.read(
            reinterpret_cast<char*>(raw.data()),
            static_cast<std::streamsize>(table_size)
        );

        if (!file) {
            throw FormatError("failed to read section headers: " + path);
        }

        if (header.section_name_index >= raw.size()) {
            throw FormatError("invalid section name index: " + path);
        }

        const auto& string_section = raw[header.section_name_index];

        if (string_section.sh_offset > file_size ||
            string_section.sh_size > file_size - string_section.sh_offset) {
            throw FormatError("section name table is outside the file");
        }

        std::vector<char> names(string_section.sh_size);

        if (!names.empty()) {
            file.seekg(static_cast<std::streamoff>(string_section.sh_offset));
            file.read(
                names.data(),
                static_cast<std::streamsize>(names.size())
            );

            if (!file) {
                throw FormatError("failed to read section names: " + path);
            }
        }

        for (const auto& entry : raw) {
            Section section;

            if (entry.sh_name < names.size()) {
                section.name = string_from_table(names, entry.sh_name);
            }

            section.type = entry.sh_type;
            section.flags = entry.sh_flags;
            section.address = entry.sh_addr;
            section.offset = entry.sh_offset;
            section.size = entry.sh_size;
            section.entry_size = entry.sh_entsize;
            section.link = entry.sh_link;
            section.info = entry.sh_info;
            section.alignment = entry.sh_addralign;

            result.push_back(std::move(section));
        }
    } else {
        const auto table_size =
            static_cast<std::uint64_t>(header.section_header_count) * sizeof(Elf32_Shdr);

        if (header.section_header_offset > file_size - table_size) {
            throw FormatError("section header table is truncated");
        }

        file.seekg(static_cast<std::streamoff>(header.section_header_offset));

        std::vector<Elf32_Shdr> raw(header.section_header_count);

        file.read(
            reinterpret_cast<char*>(raw.data()),
            static_cast<std::streamsize>(table_size)
        );

        if (!file) {
            throw FormatError("failed to read section headers: " + path);
        }

        if (header.section_name_index >= raw.size()) {
            throw FormatError("invalid section name index: " + path);
        }

        const auto& string_section = raw[header.section_name_index];

        if (string_section.sh_offset > file_size ||
            string_section.sh_size > file_size - string_section.sh_offset) {
            throw FormatError("section name table is outside the file");
        }

        std::vector<char> names(string_section.sh_size);

        if (!names.empty()) {
            file.seekg(static_cast<std::streamoff>(string_section.sh_offset));
            file.read(
                names.data(),
                static_cast<std::streamsize>(names.size())
            );

            if (!file) {
                throw FormatError("failed to read section names: " + path);
            }
        }

        for (const auto& entry : raw) {
            Section section;

            if (entry.sh_name < names.size()) {
                section.name = string_from_table(names, entry.sh_name);
            }

            section.type = entry.sh_type;
            section.flags = entry.sh_flags;
            section.address = entry.sh_addr;
            section.offset = entry.sh_offset;
            section.size = entry.sh_size;
            section.entry_size = entry.sh_entsize;
            section.link = entry.sh_link;
            section.info = entry.sh_info;
            section.alignment = entry.sh_addralign;

            result.push_back(std::move(section));
        }
    }

    return result;
}

}
