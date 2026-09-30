#pragma once

#include "section.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace elfscope {

struct SectionIssue {
    std::size_t index = 0;
    std::string name;
    std::string reason;
};

struct SectionAnalysis {
    std::size_t total = 0;
    std::size_t executable = 0;
    std::size_t writable = 0;
    std::size_t allocatable = 0;
    std::size_t nobits = 0;
    std::size_t code = 0;
    std::size_t data = 0;
    std::size_t rodata = 0;
    std::size_t tls = 0;
    std::size_t dynamic = 0;
    std::size_t symbol_tables = 0;
    std::size_t string_tables = 0;

    std::uint64_t executable_bytes = 0;
    std::uint64_t writable_bytes = 0;
    std::uint64_t allocatable_bytes = 0;
    std::uint64_t code_bytes = 0;
    std::uint64_t data_bytes = 0;
    std::uint64_t rodata_bytes = 0;

    std::vector<SectionIssue> issues;
};

SectionAnalysis analyze_sections(
    const std::vector<Section>& sections);

}
