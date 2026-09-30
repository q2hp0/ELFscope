#include "check.hpp"

#include "elfscope/dependency.hpp"
#include "elfscope/dynamic.hpp"
#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"
#include "elfscope/file_comparator.hpp"
#include "elfscope/mapping.hpp"
#include "elfscope/relocation.hpp"
#include "elfscope/security_analyzer.hpp"

#include <cstdint>
#include <random>
#include <typeinfo>

namespace {

int unexpected = 0;

// every reader may throw elfscope::Error, anything else (bad_alloc,
// out_of_range, length_error) means a size field was trusted blindly
template <typename Fn>
void attempt(const char* what, const std::string& path, Fn fn)
{
    try {
        fn();
    } catch (const elfscope::Error&) {
        // fine
    } catch (const std::exception& e) {
        std::cerr << what << " on " << path << ": unexpected "
                  << typeid(e).name() << ": " << e.what() << '\n';
        ++unexpected;
    }
}

void run_all_readers(const std::string& path)
{
    elfscope::ElfParser parser;

    attempt("parse", path, [&] { parser.parse(path); });
    attempt("sections", path, [&] { parser.sections(path); });
    attempt("segments", path, [&] { parser.segments(path); });
    attempt("interpreter", path, [&] { parser.interpreter(path); });
    attempt("symbols", path, [&] { parser.symbols(path); });
    attempt("dynamic", path, [&] { elfscope::read_dynamic_info(path); });
    attempt("relocations", path, [&] { elfscope::read_relocations(path); });
    attempt("dependencies", path, [&] { elfscope::read_dependencies(path); });
    attempt("mapping", path, [&] { elfscope::map_sections_to_segments(path); });
    attempt("security", path, [&] { elfscope::analyze_security(path); });
    attempt("compare", path, [&] {
        elfscope::compare_files(path, ELFSCOPE_SAMPLE_HARDENED);
    });
}

}

int main()
{
    const auto original = test::slurp(ELFSCOPE_SAMPLE_HARDENED);
    CHECK(original.size() > 64);

    elfscope::ElfParser parser;
    const auto header = parser.parse(ELFSCOPE_SAMPLE_HARDENED);

    test::TempFile scratch("mutant");
    std::mt19937 rng(0xE1F5C0);

    // truncations, including ones that cut a table in half
    for (std::size_t length = 0; length < original.size();
         length += (length < 512 ? 7 : original.size() / 40 + 1)) {
        scratch.write(std::vector<unsigned char>(
            original.begin(),
            original.begin() + static_cast<std::ptrdiff_t>(length)));
        run_all_readers(scratch.path());
    }

    // flips inside the ELF header and around the header tables, where
    // counts / offsets / sizes live
    std::vector<std::pair<std::uint64_t, std::uint64_t>> hot = {
        {0, 64},
        {header.program_header_offset,
         header.program_header_offset + 56ull * header.program_header_count},
        {header.section_header_offset,
         header.section_header_offset + 64ull * header.section_header_count},
    };

    for (int round = 0; round < 400; ++round) {
        auto mutant = original;
        const int flips = 1 + static_cast<int>(rng() % 4);

        for (int i = 0; i < flips; ++i) {
            const auto& range = hot[rng() % hot.size()];
            const auto end = std::min<std::uint64_t>(range.second, mutant.size());

            if (range.first >= end) {
                continue;
            }

            const auto position = range.first + rng() % (end - range.first);
            mutant[position] = static_cast<unsigned char>(rng());
        }

        scratch.write(mutant);
        run_all_readers(scratch.path());
    }

    // and some completely random damage anywhere in the file
    for (int round = 0; round < 200; ++round) {
        auto mutant = original;

        for (int i = 0; i < 8; ++i) {
            mutant[rng() % mutant.size()] = static_cast<unsigned char>(rng());
        }

        scratch.write(mutant);
        run_all_readers(scratch.path());
    }

    CHECK(unexpected == 0);

    return test::finish("malformed_tests");
}
