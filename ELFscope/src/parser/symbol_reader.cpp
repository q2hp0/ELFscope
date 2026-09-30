#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"
#include "elfscope/string_table.hpp"

#include <elf.h>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace elfscope {

std::string symbol_type_name(std::uint8_t type)
{
    switch (ELF64_ST_TYPE(type)) {
    case STT_NOTYPE:
        return "NOTYPE";
    case STT_OBJECT:
        return "OBJECT";
    case STT_FUNC:
        return "FUNC";
    case STT_SECTION:
        return "SECTION";
    case STT_FILE:
        return "FILE";
    case STT_COMMON:
        return "COMMON";
    case STT_TLS:
        return "TLS";
    case STT_GNU_IFUNC:
        return "IFUNC";
    default:
        return "UNKNOWN";
    }
}

std::string symbol_binding_name(std::uint8_t binding)
{
    switch (binding) {
    case STB_LOCAL:
        return "LOCAL";
    case STB_GLOBAL:
        return "GLOBAL";
    case STB_WEAK:
        return "WEAK";
    default:
        return "UNKNOWN";
    }
}

std::string symbol_visibility_name(std::uint8_t visibility)
{
    switch (visibility) {
    case STV_DEFAULT:
        return "DEFAULT";
    case STV_INTERNAL:
        return "INTERNAL";
    case STV_HIDDEN:
        return "HIDDEN";
    case STV_PROTECTED:
        return "PROTECTED";
    default:
        return "UNKNOWN";
    }
}

std::string symbol_section_name(std::uint16_t index)
{
    if (index == SHN_UNDEF) {
        return "UND";
    }

    if (index == SHN_ABS) {
        return "ABS";
    }

    if (index == SHN_COMMON) {
        return "COMMON";
    }

    return std::to_string(index);
}

std::vector<Symbol> ElfParser::symbols(const std::string& path) const
{
    const auto header = parse(path);
    const auto section_list = sections(path);
    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file) {
        throw FileError("can't open file: " + path);
    }

    const auto file_size = static_cast<std::uint64_t>(file.tellg());
    std::vector<Symbol> result;

    for (const auto& section : section_list) {
        if (section.type != SHT_SYMTAB && section.type != SHT_DYNSYM) {
            continue;
        }

        if (section.entry_size == 0) {
            continue;
        }

        if (section.offset > file_size ||
            section.size > file_size - section.offset) {
            throw FormatError("symbol table is outside the file");
        }

        if (section.link >= section_list.size()) {
            throw FormatError("invalid symbol string table index");
        }

        const auto& string_section = section_list[section.link];

        if (string_section.offset > file_size ||
            string_section.size > file_size - string_section.offset) {
            throw FormatError("symbol string table is outside the file");
        }

        std::vector<char> strings(string_section.size);

        if (!strings.empty()) {
            file.seekg(static_cast<std::streamoff>(string_section.offset));
            file.read(
                strings.data(),
                static_cast<std::streamsize>(strings.size())
            );

            if (!file) {
                throw FormatError("failed to read symbol strings");
            }
        }

        const auto count = section.size / section.entry_size;

        if (section.entry_size != (header.elf_class == ElfClass::elf64
            ? sizeof(Elf64_Sym)
            : sizeof(Elf32_Sym))) {
            throw FormatError("unexpected symbol entry size");
        }

        file.seekg(static_cast<std::streamoff>(section.offset));

        for (std::uint64_t i = 0; i < count; ++i) {
            Symbol symbol;

            if (header.elf_class == ElfClass::elf64) {
                Elf64_Sym raw{};

                file.read(
                    reinterpret_cast<char*>(&raw),
                    sizeof(raw)
                );

                if (!file) {
                    throw FormatError("failed to read symbol");
                }

                if (raw.st_name < strings.size()) {
                    symbol.name = string_from_table(strings, raw.st_name);
                }

                symbol.value = raw.st_value;
                symbol.size = raw.st_size;
                symbol.type = ELF64_ST_TYPE(raw.st_info);
                symbol.binding = ELF64_ST_BIND(raw.st_info);
                symbol.visibility = ELF64_ST_VISIBILITY(raw.st_other);
                symbol.section_index = raw.st_shndx;
                symbol.table = section.type == SHT_DYNSYM ? ".dynsym" : ".symtab";
            } else {
                Elf32_Sym raw{};

                file.read(
                    reinterpret_cast<char*>(&raw),
                    sizeof(raw)
                );

                if (!file) {
                    throw FormatError("failed to read symbol");
                }

                if (raw.st_name < strings.size()) {
                    symbol.name = string_from_table(strings, raw.st_name);
                }

                symbol.value = raw.st_value;
                symbol.size = raw.st_size;
                symbol.type = ELF32_ST_TYPE(raw.st_info);
                symbol.binding = ELF32_ST_BIND(raw.st_info);
                symbol.visibility = ELF32_ST_VISIBILITY(raw.st_other);
                symbol.section_index = raw.st_shndx;
                symbol.table = section.type == SHT_DYNSYM ? ".dynsym" : ".symtab";
            }

            result.push_back(std::move(symbol));
        }
    }

    return result;
}

}
