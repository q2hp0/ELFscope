#pragma once

#include "dependency.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace elfscope {

struct DependencyIssue {
    std::string name;
    std::string reason;
};

struct DependencyAnalysis {
    std::size_t count = 0;
    std::size_t unique_count = 0;
    std::size_t duplicate_count = 0;
    std::vector<std::string> names;
    std::vector<std::string> duplicates;
    std::vector<DependencyIssue> issues;
};

DependencyAnalysis analyze_dependencies(
    const std::vector<Dependency>& dependencies);

}
