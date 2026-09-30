#include "elfscope/argument_parser.hpp"

#include <algorithm>
#include <array>

namespace elfscope {

namespace {

const std::array<const char*, 11> commands = {
    "info", "sections", "segments", "mapping", "dynamic",
    "relocations", "symbols", "dependencies", "security",
    "stats", "all"
};

}

bool is_known_command(const std::string& command)
{
    if (command == "compare") {
        return true;
    }

    return std::any_of(
        commands.begin(),
        commands.end(),
        [&](const char* name) { return command == name; });
}

std::string usage_text()
{
    return
        "ELFscope - Linux ELF analysis tool\n"
        "\n"
        "usage:\n"
        "  elfscope [options] <command> <file>\n"
        "  elfscope [options] compare <file-a> <file-b>\n"
        "\n"
        "commands:\n"
        "  info          ELF header summary\n"
        "  sections      section header table\n"
        "  segments      program header table\n"
        "  mapping       which section lives in which segment\n"
        "  dynamic       dynamic section metadata\n"
        "  relocations   dynamic relocations\n"
        "  symbols       symbol tables\n"
        "  dependencies  DT_NEEDED libraries\n"
        "  security      hardening checks (PIE, NX, RELRO, canary...)\n"
        "  stats         numbers from the section/symbol/dependency analyzers\n"
        "  compare       compare two ELF files\n"
        "  all           everything above except compare\n"
        "\n"
        "options:\n"
        "  -v, --verbose   log progress to stderr\n"
        "  -V, --version   print version\n"
        "  -h, --help      show this text\n"
        "\n"
        "the analyzed file is never executed.\n";
}

Arguments ArgumentParser::parse(int argc, char** argv) const
{
    std::vector<std::string> args;

    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    return parse(args);
}

Arguments ArgumentParser::parse(const std::vector<std::string>& args) const
{
    Arguments result;
    std::vector<std::string> positional;
    bool flags_done = false;

    for (const auto& arg : args) {
        if (!flags_done && arg == "--") {
            flags_done = true;
            continue;
        }

        const bool looks_like_flag =
            !flags_done && arg.size() > 1 && arg[0] == '-';

        if (!looks_like_flag) {
            positional.push_back(arg);
            continue;
        }

        if (arg == "-h" || arg == "--help") {
            result.help = true;
        } else if (arg == "-V" || arg == "--version") {
            result.version = true;
        } else if (arg == "-v" || arg == "--verbose") {
            result.verbose = true;
        } else {
            result.error = "unknown option: " + arg;
            return result;
        }
    }

    // help and version win over everything else, even a broken command line
    if (result.help || result.version) {
        result.valid = true;
        return result;
    }

    if (positional.empty()) {
        result.error = "missing command";
        return result;
    }

    result.command = positional[0];

    if (!is_known_command(result.command)) {
        result.error = "unknown command: " + result.command;
        return result;
    }

    const std::size_t wanted = result.command == "compare" ? 2 : 1;

    if (positional.size() < wanted + 1) {
        result.error = result.command == "compare"
            ? "compare needs two files"
            : "missing file argument";
        return result;
    }

    if (positional.size() > wanted + 1) {
        result.error = "too many arguments";
        return result;
    }

    result.path = positional[1];

    if (wanted == 2) {
        result.second_path = positional[2];
    }

    result.valid = !result.path.empty();

    if (!result.valid) {
        result.error = "empty file path";
    }

    return result;
}

}
