#pragma once

#include "elf_file.hpp"
#include <string>

namespace elfscope {

ElfFile read_elf_header(const std::string& path);

}
