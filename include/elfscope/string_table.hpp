#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace elfscope {

// Reads a NUL terminated name out of a raw string table without ever
// looking past the end of it. Tables coming from damaged files are not
// guaranteed to end with a NUL byte, so plain strlen is not safe here.
inline std::string string_from_table(
    const std::vector<char>& table,
    std::uint64_t offset)
{
    if (offset >= table.size()) {
        return {};
    }

    const std::size_t start = static_cast<std::size_t>(offset);
    std::size_t end = start;

    while (end < table.size() && table[end] != '\0') {
        ++end;
    }

    return std::string(table.data() + start, end - start);
}

// same thing for tables that were read into a std::string
inline std::string string_from_table(
    const std::string& table,
    std::uint64_t offset)
{
    if (offset >= table.size()) {
        return {};
    }

    const std::size_t start = static_cast<std::size_t>(offset);
    const auto end = table.find('\0', start);

    return table.substr(
        start,
        end == std::string::npos ? std::string::npos : end - start);
}

}
