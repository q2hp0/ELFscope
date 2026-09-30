#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace elfscope {

struct FileComparison {
    bool same_bytes = false;
    bool same_size = false;
    bool same_class = false;
    bool same_endianness = false;
    bool same_machine = false;
    bool same_type = false;
    bool same_entry = false;
    bool same_section_count = false;
    bool same_segment_count = false;
    bool same_sections = false;
    bool same_segments = false;
    bool same_symbols = false;
    bool same_dependencies = false;

    std::uint64_t size_a = 0;
    std::uint64_t size_b = 0;

    std::vector<std::string> differences;
};

FileComparison compare_files(
    const std::string& first,
    const std::string& second);

}
