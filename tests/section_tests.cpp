#include "check.hpp"

#include "elfscope/elf_parser.hpp"
#include "elfscope/section_analyzer.hpp"

int main()
{
    elfscope::ElfParser parser;

    const auto sections = parser.sections("/proc/self/exe");
    const auto analysis = elfscope::analyze_sections(sections);

    CHECK(!sections.empty());
    CHECK(analysis.total == sections.size());
    CHECK(analysis.allocatable > 0);
    CHECK(analysis.executable > 0);
    CHECK(analysis.code_bytes > 0);
    CHECK(analysis.executable_bytes >= analysis.code_bytes);

    bool has_text = false;

    for (const auto& section : sections) {
        if (section.name == ".text") {
            has_text = true;
        }
    }

    CHECK(has_text);
    CHECK(elfscope::section_type_name(1) == "PROGBITS");
    CHECK(elfscope::section_flags_name(0x6).find('A') != std::string::npos);

    return test::finish("section_tests");
}
