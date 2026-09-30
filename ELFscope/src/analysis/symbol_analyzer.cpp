#include "elfscope/symbol_analyzer.hpp"

#include <elf.h>
#include <unordered_set>

namespace {

void add_issue(
    elfscope::SymbolAnalysis& result,
    const std::string& name,
    const char* reason)
{
    result.issues.push_back({
        name,
        reason
    });
}

}

namespace elfscope {

SymbolAnalysis analyze_symbols(
    const std::vector<Symbol>& symbols)
{
    SymbolAnalysis result;
    result.total = symbols.size();

    std::unordered_set<std::string> imported_seen;
    std::unordered_set<std::string> exported_seen;

    for (const auto& symbol : symbols) {
        const bool undefined =
            symbol.section_index == SHN_UNDEF;

        if (undefined) {
            ++result.undefined;

            if (!symbol.name.empty()) {
                if (imported_seen.insert(symbol.name).second) {
                    result.imported.push_back(symbol.name);
                }

                if (symbol.type == STT_FUNC ||
                    symbol.type == STT_GNU_IFUNC) {
                    ++result.imported_functions;
                }

                if (symbol.type == STT_OBJECT) {
                    ++result.imported_objects;
                }
            }
        } else {
            ++result.defined;
        }

        switch (symbol.type) {
        case STT_FUNC:
            ++result.functions;
            break;

        case STT_OBJECT:
            ++result.objects;
            break;

        case STT_TLS:
            ++result.tls;
            break;

        case STT_GNU_IFUNC:
            ++result.ifunc;
            break;

        case STT_NOTYPE:
            ++result.notype;
            break;

        default:
            break;
        }

        switch (symbol.binding) {
        case STB_GLOBAL:
            ++result.global;
            break;

        case STB_WEAK:
            ++result.weak;
            break;

        case STB_LOCAL:
            ++result.local;
            break;

        default:
            break;
        }

        if (symbol.visibility == STV_HIDDEN) {
            ++result.hidden;
        }

        const bool visible_definition =
            !undefined &&
            symbol.binding == STB_GLOBAL &&
            symbol.visibility == STV_DEFAULT &&
            !symbol.name.empty();

        if (visible_definition) {
            if (exported_seen.insert(symbol.name).second) {
                result.exported_names.push_back(symbol.name);
            }
            ++result.exported;
        }

        if (symbol.name.empty() &&
            symbol.binding != STB_LOCAL &&
            !undefined) {
            add_issue(
                result,
                symbol.name,
                "non-local defined symbol has no name");
        }
    }

    return result;
}

}
