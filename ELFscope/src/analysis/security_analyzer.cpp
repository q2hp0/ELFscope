#include "elfscope/security_analyzer.hpp"

#include "elfscope/dynamic.hpp"
#include "elfscope/elf_parser.hpp"

#include <elf.h>

#include <set>
#include <sstream>

namespace elfscope {

namespace {

bool has_flag(std::uint64_t value, std::uint64_t flag)
{
    return (value & flag) != 0;
}

// splits an rpath/runpath string on ':' and keeps empty pieces on purpose,
// an empty piece means "current directory" for the loader
std::vector<std::string> split_search_path(const std::string& text)
{
    std::vector<std::string> parts;
    std::string current;

    for (const char c : text) {
        if (c == ':') {
            parts.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }

    parts.push_back(current);
    return parts;
}

bool risky_search_entry(const std::string& entry)
{
    if (entry.empty() || entry == ".") {
        return true;
    }

    // $ORIGIN and friends are fine, absolute paths are fine
    if (entry[0] == '/' || entry[0] == '$') {
        return false;
    }

    return true;
}

void check_search_path(
    SecurityReport& report,
    const std::string& label,
    const std::string& value)
{
    if (value.empty()) {
        return;
    }

    for (const auto& entry : split_search_path(value)) {
        if (risky_search_entry(entry)) {
            report.findings.push_back(
                label + " contains a relative or empty entry: '" +
                entry + "'");
        }
    }
}

bool looks_fortified(const std::string& name)
{
    if (name.size() < 7) {
        return false;
    }

    if (name.compare(0, 2, "__") != 0) {
        return false;
    }

    if (name.compare(name.size() - 4, 4, "_chk") != 0) {
        return false;
    }

    return name.compare(0, 7, "__stack") != 0;
}

BinaryKind detect_kind(
    std::uint16_t type,
    bool has_interpreter,
    std::uint64_t flags_1)
{
    switch (type) {
    case ET_EXEC:
        return BinaryKind::executable;
    case ET_DYN:
        // static-pie has no interpreter but still carries DF_1_PIE
        if (has_interpreter || has_flag(flags_1, DF_1_PIE)) {
            return BinaryKind::pie_executable;
        }
        return BinaryKind::shared_object;
    case ET_REL:
        return BinaryKind::relocatable;
    case ET_CORE:
        return BinaryKind::core;
    default:
        return BinaryKind::other;
    }
}

}

std::string relro_name(RelroLevel level)
{
    switch (level) {
    case RelroLevel::none:
        return "none";
    case RelroLevel::partial:
        return "partial";
    case RelroLevel::full:
        return "full";
    }

    return "unknown";
}

std::string binary_kind_name(BinaryKind kind)
{
    switch (kind) {
    case BinaryKind::executable:
        return "executable (no PIE)";
    case BinaryKind::pie_executable:
        return "position independent executable";
    case BinaryKind::shared_object:
        return "shared object";
    case BinaryKind::relocatable:
        return "relocatable object";
    case BinaryKind::core:
        return "core dump";
    case BinaryKind::other:
        return "other";
    }

    return "unknown";
}

SecurityReport analyze_security(const std::string& path)
{
    ElfParser parser;

    const auto elf = parser.parse(path);
    const auto segments = parser.segments(path);
    const auto sections = parser.sections(path);
    const auto dynamic = read_dynamic_info(path);

    SecurityReport report;
    report.path = path;

    const auto interpreter = parser.interpreter(path);

    report.kind = detect_kind(
        elf.type,
        !interpreter.empty(),
        dynamic.flags_1);

    report.linked =
        report.kind == BinaryKind::executable ||
        report.kind == BinaryKind::pie_executable ||
        report.kind == BinaryKind::shared_object;

    if (!report.linked) {
        return report;
    }

    bool has_stack_header = false;
    bool has_relro = false;
    bool has_dynamic_segment = false;

    for (const auto& segment : segments) {
        if (segment.type == PT_GNU_STACK) {
            has_stack_header = true;
            report.executable_stack = has_flag(segment.flags, PF_X);
        } else if (segment.type == PT_GNU_RELRO) {
            has_relro = true;
        } else if (segment.type == PT_DYNAMIC) {
            has_dynamic_segment = true;
        }

        if (segment.type == PT_LOAD &&
            has_flag(segment.flags, PF_W) &&
            has_flag(segment.flags, PF_X)) {
            report.writable_executable = true;
        }
    }

    // no GNU_STACK header at all -> old toolchains treated that as exec stack
    if (!has_stack_header) {
        report.executable_stack = true;
    }

    report.nx = !report.executable_stack;
    report.dynamically_linked = has_dynamic_segment || !interpreter.empty();
    report.pie = report.kind == BinaryKind::pie_executable;

    if (has_relro) {
        const bool now =
            has_flag(dynamic.flags, DF_BIND_NOW) ||
            has_flag(dynamic.flags_1, DF_1_NOW);

        report.relro = now ? RelroLevel::full : RelroLevel::partial;
    }

    report.textrel = has_flag(dynamic.flags, DF_TEXTREL);
    report.rpath = dynamic.rpath;
    report.runpath = dynamic.runpath;

    report.stripped = true;

    for (const auto& section : sections) {
        if (section.type == SHT_SYMTAB) {
            report.stripped = false;
            break;
        }
    }

    // symbol based on purpose, it is a heuristic and stripping
    // a static binary can hide the canary from us
    std::set<std::string> fortified;

    for (const auto& symbol : parser.symbols(path)) {
        if (symbol.name == "__stack_chk_fail" ||
            symbol.name == "__stack_chk_guard" ||
            symbol.name == "__stack_chk_fail_local") {
            report.canary = true;
        }

        if (looks_fortified(symbol.name)) {
            fortified.insert(symbol.name);
        }
    }

    report.fortified_calls = fortified.size();
    report.fortify = !fortified.empty();

    auto& notes = report.findings;

    if (report.executable_stack) {
        notes.push_back("stack is executable (no PT_GNU_STACK or it has X)");
    }

    if (report.writable_executable) {
        notes.push_back("a PT_LOAD segment is writable and executable at once");
    }

    if (report.relro == RelroLevel::none) {
        notes.push_back("no RELRO, GOT stays writable");
    } else if (report.relro == RelroLevel::partial &&
               report.dynamically_linked) {
        notes.push_back("only partial RELRO, lazy binding keeps .got.plt writable");
    }

    if (report.kind == BinaryKind::executable) {
        notes.push_back("not position independent, fixed load address");
    }

    if (!report.canary) {
        notes.push_back("no stack protector symbols found");
    }

    if (report.textrel) {
        notes.push_back("DT_TEXTREL set, text relocations present");
    }

    if (!report.rpath.empty()) {
        notes.push_back("DT_RPATH is set (deprecated, beats LD_LIBRARY_PATH): " + report.rpath);
    }

    check_search_path(report, "RPATH", report.rpath);
    check_search_path(report, "RUNPATH", report.runpath);

    return report;
}

}
