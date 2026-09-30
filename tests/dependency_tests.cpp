#include "check.hpp"

#include "elfscope/dependency.hpp"
#include "elfscope/dependency_analyzer.hpp"

#include <algorithm>

int main()
{
    const auto dependencies = elfscope::read_dependencies(ELFSCOPE_SAMPLE_HARDENED);
    const auto analysis = elfscope::analyze_dependencies(dependencies);

    CHECK(!dependencies.empty());
    CHECK(analysis.count == dependencies.size());
    CHECK(analysis.unique_count == analysis.names.size());
    CHECK(analysis.unique_count + analysis.duplicate_count == analysis.count);

    const bool has_libc = std::any_of(
        analysis.names.begin(),
        analysis.names.end(),
        [](const std::string& name) {
            return name.rfind("libc.", 0) == 0;
        });

    CHECK(has_libc);

    // objects don't link against anything
    CHECK(elfscope::read_dependencies(ELFSCOPE_SAMPLE_OBJECT).empty());

    return test::finish("dependency_tests");
}
