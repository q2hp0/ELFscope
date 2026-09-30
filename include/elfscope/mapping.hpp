#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace elfscope {

struct SectionSegmentMapping {
    std::size_t section_index = 0;
    std::vector<std::size_t> segment_indices;
};

std::vector<SectionSegmentMapping> map_sections_to_segments(
    const std::string& path);

}
