#include "elfscope/dependency.hpp"
#include "elfscope/errors.hpp"
#include "elfscope/elf_parser.hpp"

#include <elf.h>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace elfscope {

namespace {

std::uint64_t file_size(std::ifstream& file, const std::string& path)
{
    file.seekg(0, std::ios::end);

    const auto position = file.tellg();

    if (position < 0) {
        throw FormatError("failed to determine file size: " + path);
    }

    return static_cast<std::uint64_t>(position);
}

bool contains_range(
    std::uint64_t file_size,
    std::uint64_t offset,
    std::uint64_t size)
{
    return offset <= file_size && size <= file_size - offset;
}

std::uint64_t virtual_to_file_offset(
    const std::vector<Elf64_Phdr>& headers,
    std::uint64_t address,
    std::uint64_t size,
    std::uint64_t total_size)
{
    for (const auto& header : headers) {
        if (header.p_type != PT_LOAD) {
            continue;
        }

        if (address < header.p_vaddr) {
            continue;
        }

        const auto relative = address - header.p_vaddr;

        if (relative > header.p_filesz ||
            size > header.p_filesz - relative) {
            continue;
        }

        const auto offset = header.p_offset + relative;

        if (offset < header.p_offset ||
            !contains_range(total_size, offset, size)) {
            continue;
        }

        return offset;
    }

    throw FormatError("failed to map dynamic string table into the file");
}

std::uint64_t virtual_to_file_offset(
    const std::vector<Elf32_Phdr>& headers,
    std::uint64_t address,
    std::uint64_t size,
    std::uint64_t total_size)
{
    for (const auto& header : headers) {
        if (header.p_type != PT_LOAD) {
            continue;
        }

        if (address < header.p_vaddr) {
            continue;
        }

        const auto relative = address - header.p_vaddr;

        if (relative > header.p_filesz ||
            size > header.p_filesz - relative) {
            continue;
        }

        const auto offset = static_cast<std::uint64_t>(header.p_offset) + relative;

        if (offset < header.p_offset ||
            !contains_range(total_size, offset, size)) {
            continue;
        }

        return offset;
    }

    throw FormatError("failed to map dynamic string table into the file");
}

std::string read_string(
    std::ifstream& file,
    std::uint64_t offset,
    std::uint64_t table_size,
    std::uint64_t string_offset)
{
    if (string_offset >= table_size) {
        throw FormatError("dynamic string offset is outside the string table");
    }

    const auto position = offset + string_offset;

    if (position < offset || !contains_range(table_size, string_offset, 1)) {
        throw FormatError("dynamic string offset is invalid");
    }

    file.seekg(static_cast<std::streamoff>(position));

    if (!file) {
        throw FormatError("failed to seek to dependency name");
    }

    std::string name;

    for (std::uint64_t i = string_offset; i < table_size; ++i) {
        char character = '\0';

        file.read(&character, 1);

        if (!file) {
            throw FormatError("failed to read dependency name");
        }

        if (character == '\0') {
            return name;
        }

        name.push_back(character);
    }

    throw FormatError("unterminated dependency name");
}

}

std::vector<Dependency> read_dependencies(const std::string& path)
{
    ElfParser parser;
    const auto header = parser.parse(path);

    std::ifstream file(path, std::ios::binary);

    if (!file) {
        throw FileError("can't open file: " + path);
    }

    const auto total_size = file_size(file, path);

    if (header.program_header_count == 0) {
        return {};
    }

    std::vector<Dependency> result;

    if (header.elf_class == ElfClass::elf64) {
        const auto table_size =
            static_cast<std::uint64_t>(header.program_header_count) *
            sizeof(Elf64_Phdr);

        if (!contains_range(
                total_size,
                header.program_header_offset,
                table_size)) {
            throw FormatError("program header table is outside the file");
        }

        file.seekg(static_cast<std::streamoff>(header.program_header_offset));

        std::vector<Elf64_Phdr> headers(header.program_header_count);

        file.read(
            reinterpret_cast<char*>(headers.data()),
            static_cast<std::streamsize>(table_size)
        );

        if (!file) {
            throw FormatError("failed to read program headers: " + path);
        }

        const Elf64_Phdr* dynamic = nullptr;

        for (const auto& phdr : headers) {
            if (phdr.p_type == PT_DYNAMIC) {
                dynamic = &phdr;
                break;
            }
        }

        if (!dynamic) {
            return result;
        }

        if (!contains_range(total_size, dynamic->p_offset, dynamic->p_filesz)) {
            throw FormatError("dynamic section is outside the file");
        }

        if (dynamic->p_filesz % sizeof(Elf64_Dyn) != 0) {
            throw FormatError("dynamic section is truncated");
        }

        file.seekg(static_cast<std::streamoff>(dynamic->p_offset));

        std::vector<Elf64_Dyn> entries(
            dynamic->p_filesz / sizeof(Elf64_Dyn)
        );

        file.read(
            reinterpret_cast<char*>(entries.data()),
            static_cast<std::streamsize>(dynamic->p_filesz)
        );

        if (!file) {
            throw FormatError("failed to read dynamic section: " + path);
        }

        std::uint64_t string_table_address = 0;
        std::uint64_t string_table_size = 0;
        std::vector<std::uint64_t> needed_offsets;

        for (const auto& entry : entries) {
            if (entry.d_tag == DT_STRTAB) {
                string_table_address = entry.d_un.d_ptr;
            } else if (entry.d_tag == DT_STRSZ) {
                string_table_size = entry.d_un.d_val;
            } else if (entry.d_tag == DT_NEEDED) {
                needed_offsets.push_back(entry.d_un.d_val);
            } else if (entry.d_tag == DT_NULL) {
                break;
            }
        }

        if (needed_offsets.empty()) {
            return result;
        }

        if (string_table_address == 0 || string_table_size == 0) {
            throw FormatError("dynamic string table is missing");
        }

        const auto string_table_offset = virtual_to_file_offset(
            headers,
            string_table_address,
            string_table_size,
            total_size
        );

        for (const auto offset : needed_offsets) {
            result.push_back({
                read_string(
                    file,
                    string_table_offset,
                    string_table_size,
                    offset
                )
            });
        }
    } else {
        const auto table_size =
            static_cast<std::uint64_t>(header.program_header_count) *
            sizeof(Elf32_Phdr);

        if (!contains_range(
                total_size,
                header.program_header_offset,
                table_size)) {
            throw FormatError("program header table is outside the file");
        }

        file.seekg(static_cast<std::streamoff>(header.program_header_offset));

        std::vector<Elf32_Phdr> headers(header.program_header_count);

        file.read(
            reinterpret_cast<char*>(headers.data()),
            static_cast<std::streamsize>(table_size)
        );

        if (!file) {
            throw FormatError("failed to read program headers: " + path);
        }

        const Elf32_Phdr* dynamic = nullptr;

        for (const auto& phdr : headers) {
            if (phdr.p_type == PT_DYNAMIC) {
                dynamic = &phdr;
                break;
            }
        }

        if (!dynamic) {
            return result;
        }

        if (!contains_range(total_size, dynamic->p_offset, dynamic->p_filesz)) {
            throw FormatError("dynamic section is outside the file");
        }

        if (dynamic->p_filesz % sizeof(Elf32_Dyn) != 0) {
            throw FormatError("dynamic section is truncated");
        }

        file.seekg(static_cast<std::streamoff>(dynamic->p_offset));

        std::vector<Elf32_Dyn> entries(
            dynamic->p_filesz / sizeof(Elf32_Dyn)
        );

        file.read(
            reinterpret_cast<char*>(entries.data()),
            static_cast<std::streamsize>(dynamic->p_filesz)
        );

        if (!file) {
            throw FormatError("failed to read dynamic section: " + path);
        }

        std::uint64_t string_table_address = 0;
        std::uint64_t string_table_size = 0;
        std::vector<std::uint64_t> needed_offsets;

        for (const auto& entry : entries) {
            if (entry.d_tag == DT_STRTAB) {
                string_table_address = entry.d_un.d_ptr;
            } else if (entry.d_tag == DT_STRSZ) {
                string_table_size = entry.d_un.d_val;
            } else if (entry.d_tag == DT_NEEDED) {
                needed_offsets.push_back(entry.d_un.d_val);
            } else if (entry.d_tag == DT_NULL) {
                break;
            }
        }

        if (needed_offsets.empty()) {
            return result;
        }

        if (string_table_address == 0 || string_table_size == 0) {
            throw FormatError("dynamic string table is missing");
        }

        const auto string_table_offset = virtual_to_file_offset(
            headers,
            string_table_address,
            string_table_size,
            total_size
        );

        for (const auto offset : needed_offsets) {
            result.push_back({
                read_string(
                    file,
                    string_table_offset,
                    string_table_size,
                    offset
                )
            });
        }
    }

    return result;
}

}
