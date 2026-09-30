#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace elfscope {

struct Relocation {
    std::uint64_t offset = 0;
    std::uint64_t info = 0;
    std::int64_t addend = 0;
    std::uint64_t symbol_index = 0;
    std::uint32_t type = 0;

    std::string type_name;
    std::string symbol_name;
    std::string table;
};

std::vector<Relocation> read_relocations(const std::string& path);

}
