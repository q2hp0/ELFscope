#include "elfscope/section_analyzer.hpp"

#include <elf.h>

namespace {

void add_issue(
    elfscope::SectionAnalysis& result,
    std::size_t index,
    const elfscope::Section& section,
    const char* reason)
{
    result.issues.push_back({
        index,
        section.name,
        reason
    });
}

}

namespace elfscope {

SectionAnalysis analyze_sections(
    const std::vector<Section>& sections)
{
    SectionAnalysis result;
    result.total = sections.size();

    for (std::size_t i = 0; i < sections.size(); ++i) {
        const auto& section = sections[i];

        const bool alloc =
            (section.flags & SHF_ALLOC) != 0;

        const bool write =
            (section.flags & SHF_WRITE) != 0;

        const bool execute =
            (section.flags & SHF_EXECINSTR) != 0;

        const bool tls =
            (section.flags & SHF_TLS) != 0;

        if (alloc) {
            ++result.allocatable;
            result.allocatable_bytes += section.size;
        }

        if (write) {
            result.writable_bytes += section.size;
        }

        if (execute) {
            ++result.executable;
            result.executable_bytes += section.size;
        }

        if (section.type == SHT_NOBITS) {
            ++result.nobits;
        }

        if (section.type == SHT_DYNAMIC) {
            ++result.dynamic;
        }

        if (section.type == SHT_DYNSYM ||
            section.type == SHT_SYMTAB) {
            ++result.symbol_tables;
        }

        if (section.type == SHT_STRTAB) {
            ++result.string_tables;
        }

        if (tls) {
            ++result.tls;
        }

        if (section.type == SHT_PROGBITS) {
            if (execute && alloc) {
                ++result.code;
                result.code_bytes += section.size;
            } else if (write && alloc) {
                ++result.data;
                result.data_bytes += section.size;
            } else if (alloc) {
                ++result.rodata;
                result.rodata_bytes += section.size;
            }
        }

        if (execute && write) {
            add_issue(
                result,
                i,
                section,
                "section is both writable and executable");
        }

        if (alloc &&
            section.alignment > 1 &&
            (section.address % section.alignment) != 0) {
            add_issue(
                result,
                i,
                section,
                "allocated section address is misaligned");
        }

        if (section.type != SHT_NOBITS &&
            section.size != 0 &&
            section.offset > 0 &&
            section.offset + section.size < section.offset) {
            add_issue(
                result,
                i,
                section,
                "section offset and size overflow");
        }
    }

    result.writable = 0;

    for (const auto& section : sections) {
        if ((section.flags & SHF_WRITE) != 0) {
            ++result.writable;
        }
    }

    return result;
}

}
