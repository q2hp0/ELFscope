#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"

#include <elf.h>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace elfscope {

std::string segment_type_name(std::uint32_t type)
{
    switch (type) {
    case PT_NULL:
        return "NULL";
    case PT_LOAD:
        return "LOAD";
    case PT_DYNAMIC:
        return "DYNAMIC";
    case PT_INTERP:
        return "INTERP";
    case PT_NOTE:
        return "NOTE";
    case PT_PHDR:
        return "PHDR";
    case PT_TLS:
        return "TLS";
    case PT_GNU_EH_FRAME:
        return "GNU_EH_FRAME";
    case PT_GNU_STACK:
        return "GNU_STACK";
    case PT_GNU_RELRO:
        return "GNU_RELRO";
    case PT_GNU_PROPERTY:
        return "GNU_PROPERTY";
    default:
        return "UNKNOWN";
    }
}

std::string segment_flags_name(std::uint32_t flags)
{
    std::string result;

    if (flags & PF_R) {
        result += 'R';
    }

    if (flags & PF_W) {
        result += 'W';
    }

    if (flags & PF_X) {
        result += 'E';
    }

    return result;
}

std::vector<Segment> ElfParser::segments(const std::string& path) const
{
    const auto header = parse(path);

    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file) {
        throw FileError("can't open file: " + path);
    }

    const auto position = file.tellg();

    if (position < 0) {
        throw FormatError("failed to determine file size: " + path);
    }

    const auto file_size = static_cast<std::uint64_t>(position);

    if (header.program_header_count == 0) {
        return {};
    }

    if (header.program_header_offset >= file_size) {
        throw FormatError("program header table is outside the file");
    }

    std::vector<Segment> result;

    if (header.elf_class == ElfClass::elf64) {
        const auto table_size =
            static_cast<std::uint64_t>(header.program_header_count) *
            sizeof(Elf64_Phdr);

        if (table_size > file_size - header.program_header_offset) {
            throw FormatError("program header table is truncated");
        }

        file.seekg(
            static_cast<std::streamoff>(header.program_header_offset)
        );

        std::vector<Elf64_Phdr> headers(header.program_header_count);

        file.read(
            reinterpret_cast<char*>(headers.data()),
            static_cast<std::streamsize>(table_size)
        );

        if (!file) {
            throw FormatError(
                "failed to read program headers: " + path
            );
        }

        result.reserve(headers.size());

        for (const auto& header : headers) {
            Segment segment;

            segment.type = header.p_type;
            segment.flags = header.p_flags;
            segment.offset = header.p_offset;
            segment.virtual_address = header.p_vaddr;
            segment.physical_address = header.p_paddr;
            segment.file_size = header.p_filesz;
            segment.memory_size = header.p_memsz;
            segment.alignment = header.p_align;

            result.push_back(segment);
        }
    } else {
        const auto table_size =
            static_cast<std::uint64_t>(header.program_header_count) *
            sizeof(Elf32_Phdr);

        if (table_size > file_size - header.program_header_offset) {
            throw FormatError("program header table is truncated");
        }

        file.seekg(
            static_cast<std::streamoff>(header.program_header_offset)
        );

        std::vector<Elf32_Phdr> headers(header.program_header_count);

        file.read(
            reinterpret_cast<char*>(headers.data()),
            static_cast<std::streamsize>(table_size)
        );

        if (!file) {
            throw FormatError(
                "failed to read program headers: " + path
            );
        }

        result.reserve(headers.size());

        for (const auto& header : headers) {
            Segment segment;

            segment.type = header.p_type;
            segment.flags = header.p_flags;
            segment.offset = header.p_offset;
            segment.virtual_address = header.p_vaddr;
            segment.physical_address = header.p_paddr;
            segment.file_size = header.p_filesz;
            segment.memory_size = header.p_memsz;
            segment.alignment = header.p_align;

            result.push_back(segment);
        }
    }

    return result;
}

}
