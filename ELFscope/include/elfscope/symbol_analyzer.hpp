#pragma once

#include "symbol.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace elfscope {

struct SymbolIssue {
    std::string name;
    std::string reason;
};

struct SymbolAnalysis {
    std::size_t total = 0;
    std::size_t defined = 0;
    std::size_t undefined = 0;
    std::size_t functions = 0;
    std::size_t objects = 0;
    std::size_t tls = 0;
    std::size_t ifunc = 0;
    std::size_t notype = 0;

    std::size_t global = 0;
    std::size_t weak = 0;
    std::size_t local = 0;
    std::size_t hidden = 0;

    std::size_t imported_functions = 0;
    std::size_t imported_objects = 0;
    std::size_t exported = 0;

    std::vector<std::string> imported;
    std::vector<std::string> exported_names;
    std::vector<SymbolIssue> issues;
};

SymbolAnalysis analyze_symbols(
    const std::vector<Symbol>& symbols);

}
