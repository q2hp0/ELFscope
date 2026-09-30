#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"

#include <elf.h>
#include <fstream>
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

}

static std::string read_interpreter(const std::string& path)
{
    ElfParser parser;
    const auto header = parser.parse(path);

    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file) {
        throw FileError("can't open file: " + path);
    }

    const auto end = file.tellg();

    if (end < 0) {
        throw FormatError("failed to determine file size: " + path);
    }

    const auto file_size = static_cast<std::uint64_t>(end);

    if (header.program_header_count == 0) {
        return {};
    }

    if (header.program_header_offset >= file_size) {
        throw FormatError("program header table is outside the file");
    }

    if (header.elf_class == ElfClass::elf64) {
        const auto table_size =
            static_cast<std::uint64_t>(header.program_header_count) *
            sizeof(Elf64_Phdr);

        if (!contains_range(
                file_size,
                header.program_header_offset,
                table_size)) {
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
            throw FormatError("failed to read program headers: " + path);
        }

        for (const auto& program : headers) {
            if (program.p_type != PT_INTERP) {
                continue;
            }

            if (!contains_range(
                    file_size,
                    program.p_offset,
                    program.p_filesz)) {
                throw FormatError("interpreter is outside the file");
            }

            file.seekg(
                static_cast<std::streamoff>(program.p_offset)
            );

            std::string interpreter;
            interpreter.resize(static_cast<std::size_t>(program.p_filesz));

            if (!interpreter.empty()) {
                file.read(
                    interpreter.data(),
                    static_cast<std::streamsize>(interpreter.size())
                );

                if (!file) {
                    throw FormatError(
                        "failed to read ELF interpreter: " + path
                    );
                }
            }

            const auto null_position = interpreter.find('\0');

            if (null_position != std::string::npos) {
                interpreter.resize(null_position);
            }

            return interpreter;
        }
    } else {
        const auto table_size =
            static_cast<std::uint64_t>(header.program_header_count) *
            sizeof(Elf32_Phdr);

        if (!contains_range(
                file_size,
                header.program_header_offset,
                table_size)) {
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
            throw FormatError("failed to read program headers: " + path);
        }

        for (const auto& program : headers) {
            if (program.p_type != PT_INTERP) {
                continue;
            }

            if (!contains_range(
                    file_size,
                    program.p_offset,
                    program.p_filesz)) {
                throw FormatError("interpreter is outside the file");
            }

            file.seekg(
                static_cast<std::streamoff>(program.p_offset)
            );

            std::string interpreter;
            interpreter.resize(static_cast<std::size_t>(program.p_filesz));

            if (!interpreter.empty()) {
                file.read(
                    interpreter.data(),
                    static_cast<std::streamsize>(interpreter.size())
                );

                if (!file) {
                    throw FormatError(
                        "failed to read ELF interpreter: " + path
                    );
                }
            }

            const auto null_position = interpreter.find('\0');

            if (null_position != std::string::npos) {
                interpreter.resize(null_position);
            }

            return interpreter;
        }
    }

    return {};
}

std::string ElfParser::interpreter(const std::string& path) const
{
    return read_interpreter(path);
}

}
