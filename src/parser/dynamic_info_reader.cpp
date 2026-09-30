#include "elfscope/dynamic.hpp"
#include "elfscope/errors.hpp"
#include "elfscope/elf_parser.hpp"

#include <elf.h>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace elfscope {

namespace {

bool contains_range(
    std::uint64_t file_size,
    std::uint64_t offset,
    std::uint64_t size)
{
    return offset <= file_size && size <= file_size - offset;
}

std::uint64_t checked_multiply(
    std::uint64_t left,
    std::uint64_t right)
{
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw FormatError("integer overflow while reading ELF data");
    }

    return left * right;
}

std::uint64_t checked_add(
    std::uint64_t left,
    std::uint64_t right)
{
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw FormatError("integer overflow while reading ELF data");
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

        const auto segment_start =
            static_cast<std::uint64_t>(header.p_vaddr);

        if (address < segment_start) {
            continue;
        }

        const auto relative = address - segment_start;

        if (relative > header.p_filesz ||
            size > header.p_filesz - relative) {
            continue;
        }

        const auto offset =
            checked_add(
                static_cast<std::uint64_t>(header.p_offset),
                relative
            );

        if (!contains_range(file_size, offset, size)) {
            continue;
        }

        return offset;
    }

    throw FormatError(
        "failed to map dynamic virtual address into the file"
    );
}

std::string read_dynamic_string(
    std::ifstream& file,
    std::uint64_t string_table_offset,
    std::uint64_t string_table_size,
    std::uint64_t string_offset)
{
    if (string_offset >= string_table_size) {
        throw FormatError(
            "dynamic string offset is outside the string table"
        );
    }

    const auto position =
        checked_add(string_table_offset, string_offset);

    file.seekg(static_cast<std::streamoff>(position));

    if (!file) {
        throw FormatError(
            "failed to seek to dynamic string"
        );
    }

    std::string result;

    for (std::uint64_t index = string_offset;
         index < string_table_size;
         ++index) {
        char character = '\0';

        file.read(&character, 1);

        if (!file) {
            throw FormatError(
                "failed to read dynamic string"
            );
        }

        if (character == '\0') {
            return result;
        }

        result.push_back(character);
    }

    throw FormatError(
        "unterminated dynamic string"
    );
}

void apply_dynamic_tag(
    DynamicInfo& result,
    std::int64_t tag,
    std::uint64_t value,
    std::vector<std::uint64_t>& needed,
    std::uint64_t& string_table_address,
    std::uint64_t& string_table_size)
{
    switch (tag) {
    case DT_NEEDED:
        needed.push_back(value);
        break;

    case DT_STRTAB:
        string_table_address = value;
        break;

    case DT_STRSZ:
        string_table_size = value;
        break;

    case DT_SONAME:
        result.soname = std::to_string(value);
        break;

    case DT_RPATH:
        result.rpath = std::to_string(value);
        break;

    case DT_RUNPATH:
        result.runpath = std::to_string(value);
        break;

    case DT_FLAGS:
        result.flags = value;
        break;

    case DT_FLAGS_1:
        result.flags_1 = value;
        break;

    case DT_PLTGOT:
        result.plt_got = value;
        break;

    case DT_PLTRELSZ:
        result.plt_relocation_size = value;
        break;

    case DT_RELA:
        result.rela = value;
        break;

    case DT_RELASZ:
        result.rela_size = value;
        break;

    case DT_RELAENT:
        result.rela_entry_size = value;
        break;

    case DT_REL:
        result.rel = value;
        break;

    case DT_RELSZ:
        result.rel_size = value;
        break;

    case DT_RELENT:
        result.rel_entry_size = value;
        break;

    case DT_PLTREL:
        result.plt_rel_type = value;
        break;

    case DT_JMPREL:
        result.jmprel = value;
        break;

    case DT_HASH:
        result.hash = value;
        break;

    case DT_GNU_HASH:
        result.gnu_hash = value;
        break;

    case DT_INIT:
        result.init = value;
        break;

    case DT_FINI:
        result.fini = value;
        break;

    case DT_INIT_ARRAY:
        result.init_array = value;
        break;

    case DT_INIT_ARRAYSZ:
        result.init_array_size = value;
        break;

    case DT_FINI_ARRAY:
        result.fini_array = value;
        break;

    case DT_FINI_ARRAYSZ:
        result.fini_array_size = value;
        break;

    default:
        break;
    }
}

}

DynamicInfo read_dynamic_info(const std::string& path)
{
    ElfParser parser;
    const auto elf = parser.parse(path);

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

    const auto file_size = static_cast<std::uint64_t>(end);

    DynamicInfo result;

    if (elf.program_header_count == 0) {
        return result;
    }

    if (elf.elf_class == ElfClass::elf64) {
        const auto table_size = checked_multiply(
            elf.program_header_count,
            sizeof(Elf64_Phdr)
        );

        if (!contains_range(
                file_size,
                elf.program_header_offset,
                table_size)) {
            throw FormatError(
                "program header table is outside the file"
            );
        }

        file.seekg(
            static_cast<std::streamoff>(
                elf.program_header_offset
            )
        );

        std::vector<Elf64_Phdr> headers(
            elf.program_header_count
        );

        file.read(
            reinterpret_cast<char*>(headers.data()),
            static_cast<std::streamsize>(table_size)
        );

        if (!file) {
            throw FormatError(
                "failed to read program headers: " + path
            );
        }

        const Elf64_Phdr* dynamic = nullptr;

        for (const auto& header : headers) {
            if (header.p_type == PT_DYNAMIC) {
                dynamic = &header;
                break;
            }
        }

        if (!dynamic) {
            return result;
        }

        if (!contains_range(
                file_size,
                dynamic->p_offset,
                dynamic->p_filesz)) {
            throw FormatError(
                "dynamic section is outside the file"
            );
        }

        if (dynamic->p_filesz % sizeof(Elf64_Dyn) != 0) {
            throw FormatError(
                "dynamic section has an invalid size"
            );
        }

        file.seekg(
            static_cast<std::streamoff>(dynamic->p_offset)
        );

        const auto entry_count =
            dynamic->p_filesz / sizeof(Elf64_Dyn);

        std::vector<Elf64_Dyn> entries(entry_count);

        file.read(
            reinterpret_cast<char*>(entries.data()),
            static_cast<std::streamsize>(dynamic->p_filesz)
        );

        if (!file) {
            throw FormatError(
                "failed to read dynamic entries: " + path
            );
        }

        std::uint64_t string_table_address = 0;
        std::uint64_t string_table_size = 0;
        std::vector<std::uint64_t> needed_offsets;
        std::uint64_t soname_offset =
            std::numeric_limits<std::uint64_t>::max();
        std::uint64_t rpath_offset =
            std::numeric_limits<std::uint64_t>::max();
        std::uint64_t runpath_offset =
            std::numeric_limits<std::uint64_t>::max();

        for (const auto& entry : entries) {
            ++result.entry_count;

            if (entry.d_tag == DT_NULL) {
                break;
            }

            const auto value =
                static_cast<std::uint64_t>(entry.d_un.d_val);

            if (entry.d_tag == DT_NEEDED) {
                needed_offsets.push_back(value);
                continue;
            }

            if (entry.d_tag == DT_STRTAB) {
                string_table_address = entry.d_un.d_ptr;
                continue;
            }

            if (entry.d_tag == DT_STRSZ) {
                string_table_size = value;
                continue;
            }

            if (entry.d_tag == DT_SONAME) {
                soname_offset = value;
                continue;
            }

            if (entry.d_tag == DT_RPATH) {
                rpath_offset = value;
                continue;
            }

            if (entry.d_tag == DT_RUNPATH) {
                runpath_offset = value;
                continue;
            }

            apply_dynamic_tag(
                result,
                entry.d_tag,
                value,
                needed_offsets,
                string_table_address,
                string_table_size
            );
        }

        if (string_table_address != 0 &&
            string_table_size != 0) {
            const auto string_table_offset =
                virtual_to_file(
                    headers,
                    string_table_address,
                    string_table_size,
                    file_size
                );

            for (const auto offset : needed_offsets) {
                result.needed.push_back(
                    read_dynamic_string(
                        file,
                        string_table_offset,
                        string_table_size,
                        offset
                    )
                );
            }

            if (soname_offset !=
                std::numeric_limits<std::uint64_t>::max()) {
                result.soname = read_dynamic_string(
                    file,
                    string_table_offset,
                    string_table_size,
                    soname_offset
                );
            }

            if (rpath_offset !=
                std::numeric_limits<std::uint64_t>::max()) {
                result.rpath = read_dynamic_string(
                    file,
                    string_table_offset,
                    string_table_size,
                    rpath_offset
                );
            }

            if (runpath_offset !=
                std::numeric_limits<std::uint64_t>::max()) {
                result.runpath = read_dynamic_string(
                    file,
                    string_table_offset,
                    string_table_size,
                    runpath_offset
                );
            }
        }
    } else {
        const auto table_size = checked_multiply(
            elf.program_header_count,
            sizeof(Elf32_Phdr)
        );

        if (!contains_range(
                file_size,
                elf.program_header_offset,
                table_size)) {
            throw FormatError(
                "program header table is outside the file"
            );
        }

        file.seekg(
            static_cast<std::streamoff>(
                elf.program_header_offset
            )
        );

        std::vector<Elf32_Phdr> headers(
            elf.program_header_count
        );

        file.read(
            reinterpret_cast<char*>(headers.data()),
            static_cast<std::streamsize>(table_size)
        );

        if (!file) {
            throw FormatError(
                "failed to read program headers: " + path
            );
        }

        const Elf32_Phdr* dynamic = nullptr;

        for (const auto& header : headers) {
            if (header.p_type == PT_DYNAMIC) {
                dynamic = &header;
                break;
            }
        }

        if (!dynamic) {
            return result;
        }

        if (!contains_range(
                file_size,
                dynamic->p_offset,
                dynamic->p_filesz)) {
            throw FormatError(
                "dynamic section is outside the file"
            );
        }

        if (dynamic->p_filesz % sizeof(Elf32_Dyn) != 0) {
            throw FormatError(
                "dynamic section has an invalid size"
            );
        }

        file.seekg(
            static_cast<std::streamoff>(dynamic->p_offset)
        );

        const auto entry_count =
            dynamic->p_filesz / sizeof(Elf32_Dyn);

        std::vector<Elf32_Dyn> entries(entry_count);

        file.read(
            reinterpret_cast<char*>(entries.data()),
            static_cast<std::streamsize>(dynamic->p_filesz)
        );

        if (!file) {
            throw FormatError(
                "failed to read dynamic entries: " + path
            );
        }

        std::uint64_t string_table_address = 0;
        std::uint64_t string_table_size = 0;
        std::vector<std::uint64_t> needed_offsets;
        std::uint64_t soname_offset =
            std::numeric_limits<std::uint64_t>::max();
        std::uint64_t rpath_offset =
            std::numeric_limits<std::uint64_t>::max();
        std::uint64_t runpath_offset =
            std::numeric_limits<std::uint64_t>::max();

        for (const auto& entry : entries) {
            if (entry.d_tag == DT_NULL) {
                break;
            }

            const auto value =
                static_cast<std::uint64_t>(entry.d_un.d_val);

            if (entry.d_tag == DT_NEEDED) {
                needed_offsets.push_back(value);
                continue;
            }

            if (entry.d_tag == DT_STRTAB) {
                string_table_address = value;
                continue;
            }

            if (entry.d_tag == DT_STRSZ) {
                string_table_size = value;
                continue;
            }

            if (entry.d_tag == DT_SONAME) {
                soname_offset = value;
                continue;
            }

            if (entry.d_tag == DT_RPATH) {
                rpath_offset = value;
                continue;
            }

            if (entry.d_tag == DT_RUNPATH) {
                runpath_offset = value;
                continue;
            }

            apply_dynamic_tag(
                result,
                entry.d_tag,
                value,
                needed_offsets,
                string_table_address,
                string_table_size
            );
        }

        if (string_table_address != 0 &&
            string_table_size != 0) {
            const auto string_table_offset =
                virtual_to_file(
                    headers,
                    string_table_address,
                    string_table_size,
                    file_size
                );

            for (const auto offset : needed_offsets) {
                result.needed.push_back(
                    read_dynamic_string(
                        file,
                        string_table_offset,
                        string_table_size,
                        offset
                    )
                );
            }

            if (soname_offset !=
                std::numeric_limits<std::uint64_t>::max()) {
                result.soname = read_dynamic_string(
                    file,
                    string_table_offset,
                    string_table_size,
                    soname_offset
                );
            }

            if (rpath_offset !=
                std::numeric_limits<std::uint64_t>::max()) {
                result.rpath = read_dynamic_string(
                    file,
                    string_table_offset,
                    string_table_size,
                    rpath_offset
                );
            }

            if (runpath_offset !=
                std::numeric_limits<std::uint64_t>::max()) {
                result.runpath = read_dynamic_string(
                    file,
                    string_table_offset,
                    string_table_size,
                    runpath_offset
                );
            }
        }
    }

    return result;
}

std::string dynamic_flags_name(std::uint64_t flags)
{
    std::string result;

    if (flags & DF_ORIGIN) {
        result += "ORIGIN ";
    }

    if (flags & DF_SYMBOLIC) {
        result += "SYMBOLIC ";
    }

    if (flags & DF_TEXTREL) {
        result += "TEXTREL ";
    }

    if (flags & DF_BIND_NOW) {
        result += "BIND_NOW ";
    }

    if (flags & DF_STATIC_TLS) {
        result += "STATIC_TLS ";
    }

    if (result.empty()) {
        return "none";
    }

    result.pop_back();
    return result;
}

std::string dynamic_flags_1_name(std::uint64_t flags)
{
    std::string result;

    if (flags & DF_1_NOW) {
        result += "NOW ";
    }

    if (flags & DF_1_GLOBAL) {
        result += "GLOBAL ";
    }

    if (flags & DF_1_GROUP) {
        result += "GROUP ";
    }

    if (flags & DF_1_NODELETE) {
        result += "NODELETE ";
    }

    if (flags & DF_1_LOADFLTR) {
        result += "LOADFLTR ";
    }

    if (flags & DF_1_INITFIRST) {
        result += "INITFIRST ";
    }

    if (flags & DF_1_NOOPEN) {
        result += "NOOPEN ";
    }

    if (flags & DF_1_ORIGIN) {
        result += "ORIGIN ";
    }

    if (flags & DF_1_DIRECT) {
        result += "DIRECT ";
    }

    if (flags & DF_1_INTERPOSE) {
        result += "INTERPOSE ";
    }

    if (flags & DF_1_NODEFLIB) {
        result += "NODEFLIB ";
    }

    if (flags & DF_1_NODUMP) {
        result += "NODUMP ";
    }

    if (flags & DF_1_CONFALT) {
        result += "CONFALT ";
    }

#ifdef DF_1_PIE
    if (flags & DF_1_PIE) {
        result += "PIE ";
    }
#endif

    if (result.empty()) {
        return "none";
    }

    result.pop_back();
    return result;
}

}
