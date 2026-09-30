#include "elfscope/mapping.hpp"
#include "elfscope/elf_parser.hpp"

#include <elf.h>
#include <limits>
#include <stdexcept>
#include <vector>

namespace elfscope {

namespace {

bool checked_add(
    std::uint64_t left,
    std::uint64_t right,
    std::uint64_t& result)
{
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return false;
    }

    result = left + right;
    return true;
}

bool ranges_overlap(
    std::uint64_t first_offset,
    std::uint64_t first_size,
    std::uint64_t second_offset,
    std::uint64_t second_size)
{
    if (first_size == 0 || second_size == 0) {
        return false;
    }

    std::uint64_t first_end = 0;
    std::uint64_t second_end = 0;

    if (!checked_add(first_offset, first_size, first_end) ||
        !checked_add(second_offset, second_size, second_end)) {
        return false;
    }

    return first_offset < second_end &&
           second_offset < first_end;
}

}

std::vector<SectionSegmentMapping> map_sections_to_segments(
    const std::string& path)
{
    ElfParser parser;

    const auto sections = parser.sections(path);
    const auto segments = parser.segments(path);

    std::vector<SectionSegmentMapping> result(sections.size());

    for (std::size_t section_index = 0;
         section_index < sections.size();
         ++section_index) {
        result[section_index].section_index = section_index;

        const auto& section = sections[section_index];

        for (std::size_t segment_index = 0;
             segment_index < segments.size();
             ++segment_index) {
            const auto& segment = segments[segment_index];

            if (section.type == SHT_NOBITS) {
                if (section.address >= segment.virtual_address &&
                    section.address <=
                        segment.virtual_address + segment.memory_size) {
                    result[section_index].segment_indices.push_back(
                        segment_index
                    );
                }

                continue;
            }

            if (ranges_overlap(
                    section.offset,
                    section.size,
                    segment.offset,
                    segment.file_size)) {
                result[section_index].segment_indices.push_back(
                    segment_index
                );
            }
        }
    }

    return result;
}

}
