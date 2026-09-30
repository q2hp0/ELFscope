#pragma once

#include <cstdint>
#include <string>

namespace elfscope {

struct Section {
    std::string name;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t address = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint64_t entry_size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t alignment = 0;
};

std::string section_type_name(std::uint32_t type);
std::string section_flags_name(std::uint64_t flags);

}
