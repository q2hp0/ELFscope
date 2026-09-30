#include "elfscope/command_handler.hpp"

#include "elfscope/dependency.hpp"
#include "elfscope/dependency_analyzer.hpp"
#include "elfscope/dynamic.hpp"
#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"
#include "elfscope/file_comparator.hpp"
#include "elfscope/logger.hpp"
#include "elfscope/mapping.hpp"
#include "elfscope/output_formatter.hpp"
#include "elfscope/relocation.hpp"
#include "elfscope/section_analyzer.hpp"
#include "elfscope/security_analyzer.hpp"
#include "elfscope/symbol_analyzer.hpp"

#include <functional>
#include <string>
#include <utility>
#include <vector>

#ifndef ELFSCOPE_VERSION
#define ELFSCOPE_VERSION "dev"
#endif

namespace elfscope {

namespace {

using Report = std::function<std::string(const std::string&)>;

std::string report_info(const std::string& path)
{
    ElfParser parser;

    auto elf = parser.parse(path);
    elf.interpreter = parser.interpreter(path);

    return format_info(elf);
}

std::string report_sections(const std::string& path)
{
    return format_sections(ElfParser().sections(path));
}

std::string report_segments(const std::string& path)
{
    return format_segments(ElfParser().segments(path));
}

std::string report_mapping(const std::string& path)
{
    const auto sections = ElfParser().sections(path);
    return format_mapping(sections, map_sections_to_segments(path));
}

std::string report_dynamic(const std::string& path)
{
    return format_dynamic(read_dynamic_info(path));
}

std::string report_relocations(const std::string& path)
{
    return format_relocations(read_relocations(path));
}

std::string report_symbols(const std::string& path)
{
    return format_symbols(ElfParser().symbols(path));
}

std::string report_dependencies(const std::string& path)
{
    return format_dependencies(read_dependencies(path));
}

std::string report_security(const std::string& path)
{
    return format_security(analyze_security(path));
}

std::string report_stats(const std::string& path)
{
    ElfParser parser;

    return format_stats(
        analyze_sections(parser.sections(path)),
        analyze_symbols(parser.symbols(path)),
        analyze_dependencies(read_dependencies(path)));
}

const std::vector<std::pair<std::string, Report>>& reports()
{
    static const std::vector<std::pair<std::string, Report>> table = {
        {"info", report_info},
        {"sections", report_sections},
        {"segments", report_segments},
        {"mapping", report_mapping},
        {"dynamic", report_dynamic},
        {"relocations", report_relocations},
        {"symbols", report_symbols},
        {"dependencies", report_dependencies},
        {"security", report_security},
        {"stats", report_stats}
    };

    return table;
}

// "all" keeps going when one part blows up, a weird file should still
// give us whatever else can be read from it
int run_all(const std::string& path, std::ostream& out, std::ostream& err)
{
    int status = 0;
    bool first = true;

    for (const auto& entry : reports()) {
        if (!first) {
            out << '\n';
        }

        first = false;

        try {
            out << entry.second(path);
        } catch (const Error& e) {
            err << "error: " << entry.first << ": " << e.what() << '\n';
            status = 1;
        }
    }

    return status;
}

int run_compare(
    const Arguments& arguments,
    std::ostream& out)
{
    const auto comparison = compare_files(
        arguments.path,
        arguments.second_path);

    out << format_comparison(
        arguments.path,
        arguments.second_path,
        comparison);

    return 0;
}

int run_command(
    const Arguments& arguments,
    std::ostream& out,
    std::ostream& err)
{
    info("command: " + arguments.command + " " + arguments.path);

    if (arguments.command == "compare") {
        return run_compare(arguments, out);
    }

    if (arguments.command == "all") {
        return run_all(arguments.path, out, err);
    }

    for (const auto& entry : reports()) {
        if (entry.first == arguments.command) {
            out << entry.second(arguments.path);
            return 0;
        }
    }

    err << "error: unknown command: " << arguments.command << '\n';
    return 2;
}

}

int CommandHandler::execute(
    const Arguments& arguments,
    std::ostream& out,
    std::ostream& err) const
{
    if (arguments.help) {
        out << usage_text();
        return 0;
    }

    if (arguments.version) {
        out << "elfscope " << ELFSCOPE_VERSION << '\n';
        return 0;
    }

    if (!arguments.valid) {
        if (!arguments.error.empty()) {
            err << "error: " << arguments.error << "\n\n";
        }

        err << usage_text();
        return 2;
    }

    if (arguments.verbose) {
        set_log_level(LogLevel::info);
    }

    try {
        return run_command(arguments, out, err);
    } catch (const FileError& e) {
        err << "error: " << e.what() << '\n';
        return 1;
    } catch (const Error& e) {
        err << "error: " << e.what() << '\n';
        return 1;
    } catch (const std::exception& e) {
        // should not happen, but a parser bug must not become a crash
        err << "internal error: " << e.what() << '\n';
        return 1;
    }
}

}
