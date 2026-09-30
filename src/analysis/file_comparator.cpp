#include "elfscope/file_comparator.hpp"

#include "elfscope/dependency.hpp"
#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> read_bytes(
    const std::string& path)
{
    std::ifstream input(
        path,
        std::ios::binary);

    if (!input) {
        throw elfscope::FileError(
            "cannot open file: " + path);
    }

    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

void add_difference(
    elfscope::FileComparison& result,
    const std::string& value)
{
    result.differences.push_back(value);
}

std::string section_signature(
    const elfscope::Section& section)
{
    std::ostringstream output;

    output
        << section.name << '|'
        << section.type << '|'
        << section.flags << '|'
        << section.address << '|'
        << section.offset << '|'
        << section.size << '|'
        << section.entry_size << '|'
        << section.link << '|'
        << section.info << '|'
        << section.alignment;

    return output.str();
}

std::string segment_signature(
    const elfscope::Segment& segment)
{
    std::ostringstream output;

    output
        << segment.type << '|'
        << segment.flags << '|'
        << segment.offset << '|'
        << segment.virtual_address << '|'
        << segment.physical_address << '|'
        << segment.file_size << '|'
        << segment.memory_size << '|'
        << segment.alignment;

    return output.str();
}

std::string symbol_signature(
    const elfscope::Symbol& symbol)
{
    std::ostringstream output;

    output
        << symbol.name << '|'
        << symbol.value << '|'
        << symbol.size << '|'
        << static_cast<unsigned int>(symbol.type) << '|'
        << static_cast<unsigned int>(symbol.binding) << '|'
        << static_cast<unsigned int>(symbol.visibility) << '|'
        << symbol.section_index << '|'
        << symbol.table;

    return output.str();
}

std::vector<std::string> dependency_names(
    const std::vector<elfscope::Dependency>& dependencies)
{
    std::vector<std::string> names;

    for (const auto& dependency : dependencies) {
        if (!dependency.name.empty()) {
            names.push_back(dependency.name);
        }
    }

    std::sort(names.begin(), names.end());
    names.erase(
        std::unique(names.begin(), names.end()),
        names.end());

    return names;
}

template <typename T, typename Signature>
bool same_sequence(
    const std::vector<T>& first,
    const std::vector<T>& second,
    Signature signature)
{
    if (first.size() != second.size()) {
        return false;
    }

    for (std::size_t i = 0; i < first.size(); ++i) {
        if (signature(first[i]) != signature(second[i])) {
            return false;
        }
    }

    return true;
}

}

namespace elfscope {

FileComparison compare_files(
    const std::string& first,
    const std::string& second)
{
    FileComparison result;

    const auto bytes_a = read_bytes(first);
    const auto bytes_b = read_bytes(second);

    result.size_a = bytes_a.size();
    result.size_b = bytes_b.size();

    result.same_size =
        bytes_a.size() == bytes_b.size();

    result.same_bytes =
        bytes_a == bytes_b;

    if (!result.same_bytes) {
        add_difference(
            result,
            "file contents differ");
    }

    if (!result.same_size) {
        add_difference(
            result,
            "file size differs");
    }

    ElfParser parser;

    const auto a = parser.parse(first);
    const auto b = parser.parse(second);

    result.same_class =
        a.elf_class == b.elf_class;

    result.same_endianness =
        a.endianness == b.endianness;

    result.same_machine =
        a.machine == b.machine;

    result.same_type =
        a.type == b.type;

    result.same_entry =
        a.entry == b.entry;

    result.same_section_count =
        a.section_header_count ==
        b.section_header_count;

    result.same_segment_count =
        a.program_header_count ==
        b.program_header_count;

    if (!result.same_class) {
        add_difference(result, "ELF class differs");
    }

    if (!result.same_endianness) {
        add_difference(result, "endianness differs");
    }

    if (!result.same_machine) {
        add_difference(result, "machine differs");
    }

    if (!result.same_type) {
        add_difference(result, "ELF type differs");
    }

    if (!result.same_entry) {
        add_difference(result, "entry point differs");
    }

    const auto sections_a = parser.sections(first);
    const auto sections_b = parser.sections(second);

    result.same_sections =
        same_sequence(
            sections_a,
            sections_b,
            section_signature);

    if (!result.same_sections) {
        add_difference(
            result,
            "section metadata differs");

        const auto common =
            std::min(
                sections_a.size(),
                sections_b.size());

        for (std::size_t i = 0; i < common; ++i) {
            if (section_signature(sections_a[i]) !=
                section_signature(sections_b[i])) {
                std::ostringstream message;

                message
                    << "section[" << i << "] differs";

                if (!sections_a[i].name.empty() ||
                    !sections_b[i].name.empty()) {
                    message
                        << " ("
                        << sections_a[i].name
                        << " vs "
                        << sections_b[i].name
                        << ')';
                }

                add_difference(
                    result,
                    message.str());
            }
        }

        if (sections_a.size() != sections_b.size()) {
            std::ostringstream message;

            message
                << "section count changed: "
                << sections_a.size()
                << " -> "
                << sections_b.size();

            add_difference(
                result,
                message.str());
        }
    }

    const auto segments_a = parser.segments(first);
    const auto segments_b = parser.segments(second);

    result.same_segments =
        same_sequence(
            segments_a,
            segments_b,
            segment_signature);

    if (!result.same_segments) {
        add_difference(
            result,
            "program segment metadata differs");

        const auto common =
            std::min(
                segments_a.size(),
                segments_b.size());

        for (std::size_t i = 0; i < common; ++i) {
            if (segment_signature(segments_a[i]) !=
                segment_signature(segments_b[i])) {
                std::ostringstream message;

                message
                    << "segment["
                    << i
                    << "] differs";

                add_difference(
                    result,
                    message.str());
            }
        }
    }

    const auto symbols_a = parser.symbols(first);
    const auto symbols_b = parser.symbols(second);

    result.same_symbols =
        same_sequence(
            symbols_a,
            symbols_b,
            symbol_signature);

    if (!result.same_symbols) {
        add_difference(
            result,
            "symbol tables differ");

        std::vector<std::string> names_a;
        std::vector<std::string> names_b;

        names_a.reserve(symbols_a.size());
        names_b.reserve(symbols_b.size());

        for (const auto& symbol : symbols_a) {
            names_a.push_back(symbol_signature(symbol));
        }

        for (const auto& symbol : symbols_b) {
            names_b.push_back(symbol_signature(symbol));
        }

        std::sort(names_a.begin(), names_a.end());
        std::sort(names_b.begin(), names_b.end());

        if (names_a != names_b) {
            add_difference(
                result,
                "symbol definitions or attributes changed");
        }
    }

    const auto dependencies_a =
        dependency_names(
            read_dependencies(first));

    const auto dependencies_b =
        dependency_names(
            read_dependencies(second));

    result.same_dependencies =
        dependencies_a == dependencies_b;

    if (!result.same_dependencies) {
        add_difference(
            result,
            "dynamic dependencies differ");

        for (const auto& dependency : dependencies_a) {
            if (!std::binary_search(
                    dependencies_b.begin(),
                    dependencies_b.end(),
                    dependency)) {
                add_difference(
                    result,
                    "dependency removed: " +
                    dependency);
            }
        }

        for (const auto& dependency : dependencies_b) {
            if (!std::binary_search(
                    dependencies_a.begin(),
                    dependencies_a.end(),
                    dependency)) {
                add_difference(
                    result,
                    "dependency added: " +
                    dependency);
            }
        }
    }

    return result;
}

}
