#pragma once

#include <cstdint>
#include <string>

namespace elfscope {

struct Symbol {
    std::string name;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint8_t type = 0;
    std::uint8_t binding = 0;
    std::uint8_t visibility = 0;
    std::uint16_t section_index = 0;
    std::string table;
};

std::string symbol_type_name(std::uint8_t type);
std::string symbol_binding_name(std::uint8_t binding);
std::string symbol_visibility_name(std::uint8_t visibility);
std::string symbol_section_name(std::uint16_t index);

}
