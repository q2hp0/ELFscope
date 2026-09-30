#pragma once

#include "dependency.hpp"
#include "dependency_analyzer.hpp"
#include "dynamic.hpp"
#include "elf_file.hpp"
#include "file_comparator.hpp"
#include "mapping.hpp"
#include "relocation.hpp"
#include "section.hpp"
#include "section_analyzer.hpp"
#include "security_analyzer.hpp"
#include "segment.hpp"
#include "symbol.hpp"
#include "symbol_analyzer.hpp"

#include <string>
#include <vector>

namespace elfscope {

std::string format_info(const ElfFile& elf);
std::string format_sections(const std::vector<Section>& sections);
std::string format_segments(const std::vector<Segment>& segments);

std::string format_mapping(
    const std::vector<Section>& sections,
    const std::vector<SectionSegmentMapping>& mappings);

std::string format_symbols(const std::vector<Symbol>& symbols);
std::string format_relocations(const std::vector<Relocation>& relocations);
std::string format_dependencies(const std::vector<Dependency>& dependencies);
std::string format_dynamic(const DynamicInfo& dynamic);
std::string format_security(const SecurityReport& report);

std::string format_stats(
    const SectionAnalysis& sections,
    const SymbolAnalysis& symbols,
    const DependencyAnalysis& dependencies);

std::string format_comparison(
    const std::string& first,
    const std::string& second,
    const FileComparison& comparison);

}
