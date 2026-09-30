#include "elfscope/dependency_analyzer.hpp"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace elfscope {

DependencyAnalysis analyze_dependencies(
    const std::vector<Dependency>& dependencies)
{
    DependencyAnalysis result;
    result.count = dependencies.size();

    std::unordered_map<std::string, std::size_t> counts;

    for (const auto& dependency : dependencies) {
        if (dependency.name.empty()) {
            result.issues.push_back({
                "",
                "empty dependency name"
            });
            continue;
        }

        ++counts[dependency.name];
    }

    for (const auto& [name, count] : counts) {
        result.names.push_back(name);

        if (count > 1) {
            result.duplicate_count += count - 1;
            result.duplicates.push_back(name);
        }

        if (name.find('/') != std::string::npos) {
            result.issues.push_back({
                name,
                "dependency contains an explicit path"
            });
        }
    }

    std::sort(result.names.begin(), result.names.end());
    std::sort(result.duplicates.begin(), result.duplicates.end());

    result.unique_count = result.names.size();

    return result;
}

}
