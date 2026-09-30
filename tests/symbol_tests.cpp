#include "check.hpp"

#include "elfscope/elf_parser.hpp"
#include "elfscope/symbol_analyzer.hpp"

int main()
{
    elfscope::ElfParser parser;

    const auto symbols = parser.symbols("/proc/self/exe");
    const auto analysis = elfscope::analyze_symbols(symbols);

    CHECK(!symbols.empty());
    CHECK(analysis.total == symbols.size());
    CHECK(analysis.defined + analysis.undefined == analysis.total);
    CHECK(analysis.undefined > 0);
    CHECK(analysis.functions > 0);
    CHECK(analysis.imported_functions > 0);

    // the object file has a real symbol table with main in it
    const auto object_symbols = parser.symbols(ELFSCOPE_SAMPLE_OBJECT);
    bool found_main = false;

    for (const auto& symbol : object_symbols) {
        if (symbol.name == "main") {
            found_main = true;
        }
    }

    CHECK(found_main);

    return test::finish("symbol_tests");
}
