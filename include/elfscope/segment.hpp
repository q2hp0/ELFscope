#pragma once

#include <cstdint>
#include <string>

namespace elfscope {

struct Segment {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t physical_address = 0;
    std::uint64_t file_size = 0;
    std::uint64_t memory_size = 0;
    std::uint64_t alignment = 0;
};

std::string segment_type_name(std::uint32_t type);
std::string segment_flags_name(std::uint32_t flags);

}
