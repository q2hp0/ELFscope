#include "elfscope/relocation.hpp"
#include "elfscope/errors.hpp"
#include "elfscope/string_table.hpp"
#include "elfscope/dynamic.hpp"
#include "elfscope/elf_parser.hpp"
#include "elfscope/section.hpp"

#include <elf.h>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace elfscope {

namespace {

struct DynamicSymbol {
    std::string name;
};

bool contains_range(
    std::uint64_t file_size,
    std::uint64_t offset,
    std::uint64_t size)
{
    return offset <= file_size && size <= file_size - offset;
}

std::uint64_t checked_add(
    std::uint64_t left,
    std::uint64_t right)
{
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw FormatError("ELF integer overflow");
    }

    return left + right;
}

template <typename ProgramHeader>
std::uint64_t virtual_to_file(
    const std::vector<ProgramHeader>& headers,
    std::uint64_t address,
    std::uint64_t size,
    std::uint64_t file_size)
{
    for (const auto& header : headers) {
        if (header.p_type != PT_LOAD) {
            continue;
        }

        const auto start =
            static_cast<std::uint64_t>(header.p_vaddr);

        if (address < start) {
            continue;
        }

        const auto relative = address - start;

        if (relative > header.p_filesz ||
            size > header.p_filesz - relative) {
            continue;
        }

        const auto offset = checked_add(
            static_cast<std::uint64_t>(header.p_offset),
            relative
        );

        if (!contains_range(file_size, offset, size)) {
            continue;
        }

        return offset;
    }

    throw FormatError(
        "failed to map relocation address into file"
    );
}

std::string x86_64_relocation_name(std::uint32_t type)
{
    switch (type) {
    case R_X86_64_NONE:
        return "NONE";
    case R_X86_64_64:
        return "64";
    case R_X86_64_PC32:
        return "PC32";
    case R_X86_64_GOT32:
        return "GOT32";
    case R_X86_64_PLT32:
        return "PLT32";
    case R_X86_64_COPY:
        return "COPY";
    case R_X86_64_GLOB_DAT:
        return "GLOB_DAT";
    case R_X86_64_JUMP_SLOT:
        return "JUMP_SLOT";
    case R_X86_64_RELATIVE:
        return "RELATIVE";
    case R_X86_64_GOTPCREL:
        return "GOTPCREL";
    case R_X86_64_32:
        return "32";
    case R_X86_64_32S:
        return "32S";
    case R_X86_64_16:
        return "16";
    case R_X86_64_PC16:
        return "PC16";
    case R_X86_64_8:
        return "8";
    case R_X86_64_PC8:
        return "PC8";
    case R_X86_64_DTPMOD64:
        return "DTPMOD64";
    case R_X86_64_DTPOFF64:
        return "DTPOFF64";
    case R_X86_64_TPOFF64:
        return "TPOFF64";
    case R_X86_64_TLSGD:
        return "TLSGD";
    case R_X86_64_TLSLD:
        return "TLSLD";
    case R_X86_64_DTPOFF32:
        return "DTPOFF32";
    case R_X86_64_GOTTPOFF:
        return "GOTTPOFF";
    case R_X86_64_TPOFF32:
        return "TPOFF32";
    case R_X86_64_IRELATIVE:
        return "IRELATIVE";
    case R_X86_64_RELATIVE64:
        return "RELATIVE64";
    default:
        return "UNKNOWN";
    }
}

std::string i386_relocation_name(std::uint32_t type)
{
    switch (type) {
    case R_386_NONE:
        return "NONE";
    case R_386_32:
        return "32";
    case R_386_PC32:
        return "PC32";
    case R_386_GOT32:
        return "GOT32";
    case R_386_PLT32:
        return "PLT32";
    case R_386_COPY:
        return "COPY";
    case R_386_GLOB_DAT:
        return "GLOB_DAT";
    case R_386_JMP_SLOT:
        return "JMP_SLOT";
    case R_386_RELATIVE:
        return "RELATIVE";
    case R_386_GOTOFF:
        return "GOTOFF";
    case R_386_GOTPC:
        return "GOTPC";
    case R_386_TLS_TPOFF:
        return "TLS_TPOFF";
    case R_386_TLS_IE:
        return "TLS_IE";
    case R_386_TLS_GOTIE:
        return "TLS_GOTIE";
    case R_386_TLS_LE:
        return "TLS_LE";
    case R_386_TLS_GD:
        return "TLS_GD";
    case R_386_TLS_LDM:
        return "TLS_LDM";
    case R_386_TLS_GD_32:
        return "TLS_GD_32";
    case R_386_TLS_GD_PUSH:
        return "TLS_GD_PUSH";
    case R_386_TLS_GD_CALL:
        return "TLS_GD_CALL";
    case R_386_TLS_GD_POP:
        return "TLS_GD_POP";
    case R_386_TLS_LDM_32:
        return "TLS_LDM_32";
    case R_386_TLS_LDM_PUSH:
        return "TLS_LDM_PUSH";
    case R_386_TLS_LDM_CALL:
        return "TLS_LDM_CALL";
    case R_386_TLS_LDM_POP:
        return "TLS_LDM_POP";
    case R_386_TLS_LDO_32:
        return "TLS_LDO_32";
    case R_386_TLS_IE_32:
        return "TLS_IE_32";
    case R_386_TLS_LE_32:
        return "TLS_LE_32";
    case R_386_TLS_DTPMOD32:
        return "TLS_DTPMOD32";
    case R_386_TLS_DTPOFF32:
        return "TLS_DTPOFF32";
    case R_386_TLS_TPOFF32:
        return "TLS_TPOFF32";
    default:
        return "UNKNOWN";
    }
}

std::string aarch64_relocation_name(std::uint32_t type)
{
    switch (type) {
    case R_AARCH64_NONE:
        return "NONE";
    case R_AARCH64_ABS64:
        return "ABS64";
    case R_AARCH64_ABS32:
        return "ABS32";
    case R_AARCH64_ABS16:
        return "ABS16";
    case R_AARCH64_PREL64:
        return "PREL64";
    case R_AARCH64_PREL32:
        return "PREL32";
    case R_AARCH64_PREL16:
        return "PREL16";
    case R_AARCH64_COPY:
        return "COPY";
    case R_AARCH64_GLOB_DAT:
        return "GLOB_DAT";
    case R_AARCH64_JUMP_SLOT:
        return "JUMP_SLOT";
    case R_AARCH64_RELATIVE:
        return "RELATIVE";
    case R_AARCH64_IRELATIVE:
        return "IRELATIVE";
    default:
        return "UNKNOWN";
    }
}

std::string arm_relocation_name(std::uint32_t type)
{
    switch (type) {
    case R_ARM_NONE:
        return "NONE";
    case R_ARM_PC24:
        return "PC24";
    case R_ARM_ABS32:
        return "ABS32";
    case R_ARM_REL32:
        return "REL32";
    case R_ARM_ABS16:
        return "ABS16";
    case R_ARM_ABS12:
        return "ABS12";
    case R_ARM_THM_ABS5:
        return "THM_ABS5";
    case R_ARM_ABS8:
        return "ABS8";
    case R_ARM_SBREL32:
        return "SBREL32";
    case R_ARM_THM_PC8:
        return "THM_PC8";
    case R_ARM_TLS_DTPMOD32:
        return "TLS_DTPMOD32";
    case R_ARM_TLS_DTPOFF32:
        return "TLS_DTPOFF32";
    case R_ARM_TLS_TPOFF32:
        return "TLS_TPOFF32";
    case R_ARM_COPY:
        return "COPY";
    case R_ARM_GLOB_DAT:
        return "GLOB_DAT";
    case R_ARM_JUMP_SLOT:
        return "JUMP_SLOT";
    case R_ARM_RELATIVE:
        return "RELATIVE";
    case R_ARM_GOTOFF:
        return "GOTOFF";
    case R_ARM_GOTPC:
        return "GOTPC";
    case R_ARM_GOT32:
        return "GOT32";
    case R_ARM_PLT32:
        return "PLT32";
    case R_ARM_CALL:
        return "CALL";
    case R_ARM_JUMP24:
        return "JUMP24";
    case R_ARM_V4BX:
        return "V4BX";
    case R_ARM_THM_JUMP19:
        return "THM_JUMP19";
    case R_ARM_THM_JUMP24:
        return "THM_JUMP24";
    case R_ARM_THM_MOVW_ABS_NC:
        return "THM_MOVW_ABS_NC";
    case R_ARM_THM_MOVT_ABS:
        return "THM_MOVT_ABS";
    case R_ARM_MOVW_ABS_NC:
        return "MOVW_ABS_NC";
    case R_ARM_MOVT_ABS:
        return "MOVT_ABS";
    case R_ARM_IRELATIVE:
        return "IRELATIVE";
    default:
        return "UNKNOWN";
    }
}

std::string relocation_type_name(
    std::uint16_t machine,
    std::uint32_t type)
{
    switch (machine) {
    case EM_X86_64:
        return "R_X86_64_" + x86_64_relocation_name(type);
    case EM_386:
        return "R_386_" + i386_relocation_name(type);
    case EM_AARCH64:
        return "R_AARCH64_" + aarch64_relocation_name(type);
    case EM_ARM:
        return "R_ARM_" + arm_relocation_name(type);
    default:
        return "UNKNOWN";
    }
}

template <typename Symbol>
std::vector<DynamicSymbol> read_dynamic_symbols(
    std::ifstream& file,
    const Section& symbol_section,
    const Section& string_section,
    std::uint64_t file_size)
{
    if (symbol_section.entry_size == 0) {
        throw FormatError(
            "dynamic symbol table has zero entry size"
        );
    }

    if (symbol_section.size % symbol_section.entry_size != 0) {
        throw FormatError(
            "dynamic symbol table has invalid size"
        );
    }

    if (!contains_range(
            file_size,
            symbol_section.offset,
            symbol_section.size)) {
        throw FormatError(
            "dynamic symbol table is outside the file"
        );
    }

    if (!contains_range(
            file_size,
            string_section.offset,
            string_section.size)) {
        throw FormatError(
            "dynamic string table is outside the file"
        );
    }

    file.seekg(
        static_cast<std::streamoff>(string_section.offset)
    );

    std::string strings;
    strings.resize(
        static_cast<std::size_t>(string_section.size)
    );

    if (!strings.empty()) {
        file.read(
            strings.data(),
            static_cast<std::streamsize>(strings.size())
        );

        if (!file) {
            throw FormatError(
                "failed to read dynamic string table"
            );
        }
    }

    const auto count =
        symbol_section.size / symbol_section.entry_size;

    std::vector<DynamicSymbol> result;
    result.reserve(static_cast<std::size_t>(count));

    file.seekg(
        static_cast<std::streamoff>(symbol_section.offset)
    );

    for (std::uint64_t index = 0; index < count; ++index) {
        result.emplace_back();

        if constexpr (sizeof(Symbol) == sizeof(Elf64_Sym)) {
            Elf64_Sym symbol{};

            file.read(
                reinterpret_cast<char*>(&symbol),
                sizeof(symbol)
            );

            if (!file) {
                throw FormatError(
                    "failed to read dynamic symbol"
                );
            }

            if (symbol.st_name >= strings.size()) {
                throw FormatError(
                    "dynamic symbol name is outside string table"
                );
            }

            result.back().name = string_from_table(strings, symbol.st_name);
        } else {
            Elf32_Sym symbol{};

            file.read(
                reinterpret_cast<char*>(&symbol),
                sizeof(symbol)
            );

            if (!file) {
                throw FormatError(
                    "failed to read dynamic symbol"
                );
            }

            if (symbol.st_name >= strings.size()) {
                throw FormatError(
                    "dynamic symbol name is outside string table"
                );
            }

            result.back().name = string_from_table(strings, symbol.st_name);
        }
    }

    return result;
}

std::vector<DynamicSymbol> load_dynamic_symbols(
    std::ifstream& file,
    const std::vector<Section>& sections,
    ElfClass elf_class,
    std::uint64_t file_size)
{
    const Section* symbol_section = nullptr;

    for (const auto& section : sections) {
        if (section.type == SHT_DYNSYM) {
            symbol_section = &section;
            break;
        }
    }

    if (!symbol_section) {
        return {};
    }

    if (symbol_section->link >= sections.size()) {
        throw FormatError(
            "dynamic symbol string table index is invalid"
        );
    }

    const auto& string_section =
        sections[symbol_section->link];

    if (string_section.type != SHT_STRTAB) {
        throw FormatError(
            "dynamic symbol string table has invalid type"
        );
    }

    if (elf_class == ElfClass::elf64) {
        return read_dynamic_symbols<Elf64_Sym>(
            file,
            *symbol_section,
            string_section,
            file_size
        );
    }

    return read_dynamic_symbols<Elf32_Sym>(
        file,
        *symbol_section,
        string_section,
        file_size
    );
}

void read_rela_table(
    std::ifstream& file,
    std::uint64_t file_offset,
    std::uint64_t size,
    std::uint64_t entry_size,
    std::uint64_t jmprel,
    std::uint64_t table_address,
    std::uint16_t machine,
    const std::vector<DynamicSymbol>& symbols,
    const std::string& table_name,
    std::uint64_t file_size,
    std::vector<Relocation>& result,
    bool elf64)
{
    if (entry_size == 0) {
        throw FormatError(
            "RELA entry size is zero"
        );
    }

    if (size % entry_size != 0) {
        throw FormatError(
            "RELA table has invalid size"
        );
    }

    if (!contains_range(file_size, file_offset, size)) {
        throw FormatError(
            "RELA table is outside the file"
        );
    }

    const auto count = size / entry_size;

    file.seekg(
        static_cast<std::streamoff>(file_offset)
    );

    for (std::uint64_t index = 0; index < count; ++index) {
        Relocation relocation;

        if (elf64) {
            if (entry_size < sizeof(Elf64_Rela)) {
                throw FormatError(
                    "RELA64 entry is smaller than expected"
                );
            }

            Elf64_Rela raw{};

            file.read(
                reinterpret_cast<char*>(&raw),
                sizeof(raw)
            );

            if (!file) {
                throw FormatError(
                    "failed to read RELA64 entry"
                );
            }

            if (entry_size > sizeof(raw)) {
                file.seekg(
                    static_cast<std::streamoff>(
                        entry_size - sizeof(raw)
                    ),
                    std::ios::cur
                );

                if (!file) {
                    throw FormatError(
                        "failed to skip extended RELA64 entry"
                    );
                }
            }

            relocation.offset = raw.r_offset;
            relocation.info = raw.r_info;
            relocation.addend = raw.r_addend;
            relocation.symbol_index = ELF64_R_SYM(raw.r_info);
            relocation.type = ELF64_R_TYPE(raw.r_info);
        } else {
            if (entry_size < sizeof(Elf32_Rela)) {
                throw FormatError(
                    "RELA32 entry is smaller than expected"
                );
            }

            Elf32_Rela raw{};

            file.read(
                reinterpret_cast<char*>(&raw),
                sizeof(raw)
            );

            if (!file) {
                throw FormatError(
                    "failed to read RELA32 entry"
                );
            }

            if (entry_size > sizeof(raw)) {
                file.seekg(
                    static_cast<std::streamoff>(
                        entry_size - sizeof(raw)
                    ),
                    std::ios::cur
                );

                if (!file) {
                    throw FormatError(
                        "failed to skip extended RELA32 entry"
                    );
                }
            }

            relocation.offset = raw.r_offset;
            relocation.info = raw.r_info;
            relocation.addend = raw.r_addend;
            relocation.symbol_index = ELF32_R_SYM(raw.r_info);
            relocation.type = ELF32_R_TYPE(raw.r_info);
        }

        relocation.type_name =
            relocation_type_name(
                machine,
                relocation.type
            );

        if (relocation.symbol_index < symbols.size()) {
            relocation.symbol_name =
                symbols[relocation.symbol_index].name;
        } else if (relocation.symbol_index == 0) {
            relocation.symbol_name.clear();
        } else {
            relocation.symbol_name =
                "<invalid-symbol-index>";
        }

        if (table_address == jmprel && jmprel != 0) {
            relocation.table = table_name + ".plt";
        } else {
            relocation.table = table_name + ".dyn";
        }

        result.push_back(std::move(relocation));
    }
}

void read_rel_table(
    std::ifstream& file,
    std::uint64_t file_offset,
    std::uint64_t size,
    std::uint64_t entry_size,
    std::uint64_t jmprel,
    std::uint64_t table_address,
    std::uint16_t machine,
    const std::vector<DynamicSymbol>& symbols,
    const std::string& table_name,
    std::uint64_t file_size,
    std::vector<Relocation>& result,
    bool elf64)
{
    if (entry_size == 0) {
        throw FormatError(
            "REL entry size is zero"
        );
    }

    if (!contains_range(file_size, file_offset, size)) {
        throw FormatError(
            "REL table is outside the file"
        );
    }

    if (size % entry_size != 0) {
        throw FormatError(
            "REL table has invalid size"
        );
    }

    const auto count = size / entry_size;

    file.seekg(
        static_cast<std::streamoff>(file_offset)
    );

    for (std::uint64_t index = 0; index < count; ++index) {
        Relocation relocation;

        if (elf64) {
            if (entry_size < sizeof(Elf64_Rel)) {
                throw FormatError(
                    "REL64 entry is smaller than expected"
                );
            }

            Elf64_Rel raw{};

            file.read(
                reinterpret_cast<char*>(&raw),
                sizeof(raw)
            );

            if (!file) {
                throw FormatError(
                    "failed to read REL64 entry"
                );
            }

            if (entry_size > sizeof(raw)) {
                file.seekg(
                    static_cast<std::streamoff>(
                        entry_size - sizeof(raw)
                    ),
                    std::ios::cur
                );
            }

            relocation.offset = raw.r_offset;
            relocation.info = raw.r_info;
            relocation.symbol_index =
                ELF64_R_SYM(raw.r_info);
            relocation.type =
                ELF64_R_TYPE(raw.r_info);
        } else {
            if (entry_size < sizeof(Elf32_Rel)) {
                throw FormatError(
                    "REL32 entry is smaller than expected"
                );
            }

            Elf32_Rel raw{};

            file.read(
                reinterpret_cast<char*>(&raw),
                sizeof(raw)
            );

            if (!file) {
                throw FormatError(
                    "failed to read REL32 entry"
                );
            }

            if (entry_size > sizeof(raw)) {
                file.seekg(
                    static_cast<std::streamoff>(
                        entry_size - sizeof(raw)
                    ),
                    std::ios::cur
                );
            }

            relocation.offset = raw.r_offset;
            relocation.info = raw.r_info;
            relocation.symbol_index =
                ELF32_R_SYM(raw.r_info);
            relocation.type =
                ELF32_R_TYPE(raw.r_info);
        }

        relocation.type_name =
            relocation_type_name(machine, relocation.type);

        if (relocation.symbol_index < symbols.size()) {
            relocation.symbol_name =
                symbols[relocation.symbol_index].name;
        } else if (relocation.symbol_index == 0) {
            relocation.symbol_name.clear();
        } else {
            relocation.symbol_name = "<invalid-symbol-index>";
        }

        if (table_address == jmprel && jmprel != 0) {
            relocation.table = table_name + ".plt";
        } else {
            relocation.table = table_name + ".dyn";
        }

        result.push_back(std::move(relocation));
    }
}

}

std::vector<Relocation> read_relocations(const std::string& path)
{
    ElfParser parser;
    const auto elf = parser.parse(path);
    const auto sections = parser.sections(path);
    const auto dynamic = read_dynamic_info(path);

    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file) {
        throw FileError("can't open file: " + path);
    }

    const auto end = file.tellg();

    if (end < 0) {
        throw FormatError(
            "failed to determine file size: " + path
        );
    }

    const auto file_size =
        static_cast<std::uint64_t>(end);

    std::vector<Relocation> result;

    if (dynamic.rela != 0 && dynamic.rela_size != 0) {
        std::uint64_t program_offset = 0;

        if (elf.elf_class == ElfClass::elf64) {
            const auto segments = parser.segments(path);

            std::vector<Elf64_Phdr> headers;
            headers.reserve(segments.size());

            file.seekg(0);

            for (const auto& segment : segments) {
                Elf64_Phdr header{};
                header.p_type = segment.type;
                header.p_flags = segment.flags;
                header.p_offset = segment.offset;
                header.p_vaddr = segment.virtual_address;
                header.p_paddr = segment.physical_address;
                header.p_filesz = segment.file_size;
                header.p_memsz = segment.memory_size;
                header.p_align = segment.alignment;
                headers.push_back(header);
            }

            program_offset = virtual_to_file(
                headers,
                dynamic.rela,
                dynamic.rela_size,
                file_size
            );
        } else {
            const auto segments = parser.segments(path);

            std::vector<Elf32_Phdr> headers;
            headers.reserve(segments.size());

            for (const auto& segment : segments) {
                Elf32_Phdr header{};
                header.p_type = segment.type;
                header.p_flags = segment.flags;
                header.p_offset = segment.offset;
                header.p_vaddr = segment.virtual_address;
                header.p_paddr = segment.physical_address;
                header.p_filesz = segment.file_size;
                header.p_memsz = segment.memory_size;
                header.p_align = segment.alignment;
                headers.push_back(header);
            }

            program_offset = virtual_to_file(
                headers,
                dynamic.rela,
                dynamic.rela_size,
                file_size
            );
        }

        const auto symbols =
            load_dynamic_symbols(
                file,
                sections,
                elf.elf_class,
                file_size
            );

        read_rela_table(
            file,
            program_offset,
            dynamic.rela_size,
            dynamic.rela_entry_size,
            dynamic.jmprel,
            dynamic.rela,
            elf.machine,
            symbols,
            "rela",
            file_size,
            result,
            elf.elf_class == ElfClass::elf64
        );
    }

    if (dynamic.rel != 0 && dynamic.rel_size != 0) {
        std::uint64_t program_offset = 0;

        if (elf.elf_class == ElfClass::elf64) {
            const auto segments = parser.segments(path);

            std::vector<Elf64_Phdr> headers;
            headers.reserve(segments.size());

            for (const auto& segment : segments) {
                Elf64_Phdr header{};
                header.p_type = segment.type;
                header.p_flags = segment.flags;
                header.p_offset = segment.offset;
                header.p_vaddr = segment.virtual_address;
                header.p_paddr = segment.physical_address;
                header.p_filesz = segment.file_size;
                header.p_memsz = segment.memory_size;
                header.p_align = segment.alignment;
                headers.push_back(header);
            }

            program_offset = virtual_to_file(
                headers,
                dynamic.rel,
                dynamic.rel_size,
                file_size
            );
        } else {
            const auto segments = parser.segments(path);

            std::vector<Elf32_Phdr> headers;
            headers.reserve(segments.size());

            for (const auto& segment : segments) {
                Elf32_Phdr header{};
                header.p_type = segment.type;
                header.p_flags = segment.flags;
                header.p_offset = segment.offset;
                header.p_vaddr = segment.virtual_address;
                header.p_paddr = segment.physical_address;
                header.p_filesz = segment.file_size;
                header.p_memsz = segment.memory_size;
                header.p_align = segment.alignment;
                headers.push_back(header);
            }

            program_offset = virtual_to_file(
                headers,
                dynamic.rel,
                dynamic.rel_size,
                file_size
            );
        }

        const auto symbols =
            load_dynamic_symbols(
                file,
                sections,
                elf.elf_class,
                file_size
            );

        read_rel_table(
            file,
            program_offset,
            dynamic.rel_size,
            dynamic.rel_entry_size,
            dynamic.jmprel,
            dynamic.rel,
            elf.machine,
            symbols,
            "rel",
            file_size,
            result,
            elf.elf_class == ElfClass::elf64
        );
    }

    if (dynamic.jmprel != 0 && dynamic.plt_relocation_size != 0) {
        const auto segments = parser.segments(path);

        if (elf.elf_class == ElfClass::elf64) {
            std::vector<Elf64_Phdr> headers;
            headers.reserve(segments.size());

            for (const auto& segment : segments) {
                Elf64_Phdr header{};
                header.p_type = segment.type;
                header.p_flags = segment.flags;
                header.p_offset = segment.offset;
                header.p_vaddr = segment.virtual_address;
                header.p_paddr = segment.physical_address;
                header.p_filesz = segment.file_size;
                header.p_memsz = segment.memory_size;
                header.p_align = segment.alignment;
                headers.push_back(header);
            }

            const auto offset = virtual_to_file(
                headers,
                dynamic.jmprel,
                dynamic.plt_relocation_size,
                file_size
            );

            const auto symbols =
                load_dynamic_symbols(
                    file,
                    sections,
                    elf.elf_class,
                    file_size
                );

            if (dynamic.plt_rel_type == DT_RELA) {
                read_rela_table(
                    file,
                    offset,
                    dynamic.plt_relocation_size,
                    dynamic.rela_entry_size,
                    dynamic.jmprel,
                    dynamic.jmprel,
                    elf.machine,
                    symbols,
                    "rela",
                    file_size,
                    result,
                    true
                );
            } else if (dynamic.plt_rel_type == DT_REL) {
                read_rel_table(
                    file,
                    offset,
                    dynamic.plt_relocation_size,
                    dynamic.rel_entry_size,
                    dynamic.jmprel,
                    dynamic.jmprel,
                    elf.machine,
                    symbols,
                    "rel",
                    file_size,
                    result,
                    true
                );
            }
        } else {
            std::vector<Elf32_Phdr> headers;
            headers.reserve(segments.size());

            for (const auto& segment : segments) {
                Elf32_Phdr header{};
                header.p_type = segment.type;
                header.p_flags = segment.flags;
                header.p_offset = segment.offset;
                header.p_vaddr = segment.virtual_address;
                header.p_paddr = segment.physical_address;
                header.p_filesz = segment.file_size;
                header.p_memsz = segment.memory_size;
                header.p_align = segment.alignment;
                headers.push_back(header);
            }

            const auto offset = virtual_to_file(
                headers,
                dynamic.jmprel,
                dynamic.plt_relocation_size,
                file_size
            );

            const auto symbols =
                load_dynamic_symbols(
                    file,
                    sections,
                    elf.elf_class,
                    file_size
                );

            if (dynamic.plt_rel_type == DT_RELA) {
                read_rela_table(
                    file,
                    offset,
                    dynamic.plt_relocation_size,
                    dynamic.rela_entry_size,
                    dynamic.jmprel,
                    dynamic.jmprel,
                    elf.machine,
                    symbols,
                    "rela",
                    file_size,
                    result,
                    false
                );
            } else if (dynamic.plt_rel_type == DT_REL) {
                read_rel_table(
                    file,
                    offset,
                    dynamic.plt_relocation_size,
                    dynamic.rel_entry_size,
                    dynamic.jmprel,
                    dynamic.jmprel,
                    elf.machine,
                    symbols,
                    "rel",
                    file_size,
                    result,
                    false
                );
            }
        }
    }

    return result;
}

}
