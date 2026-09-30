#include "elfscope/header_reader.hpp"
#include "elfscope/elf_parser.hpp"

namespace elfscope {

ElfFile read_elf_header(const std::string& path)
{
    ElfParser parser;
    return parser.parse(path);
}

}
