#include "check.hpp"

#include "elfscope/security_analyzer.hpp"

#include <algorithm>

namespace {

bool mentions(const elfscope::SecurityReport& report, const std::string& text)
{
    return std::any_of(
        report.findings.begin(),
        report.findings.end(),
        [&](const std::string& finding) {
            return finding.find(text) != std::string::npos;
        });
}

}

int main()
{
    const auto good = elfscope::analyze_security(ELFSCOPE_SAMPLE_HARDENED);

    CHECK(good.linked);
    CHECK(good.dynamically_linked);
    CHECK(good.pie);
    CHECK(good.nx);
    CHECK(good.relro == elfscope::RelroLevel::full);
    CHECK(good.canary);
    CHECK(!good.executable_stack);
    CHECK(good.findings.empty());

    const auto bad = elfscope::analyze_security(ELFSCOPE_SAMPLE_WEAK);

    CHECK(bad.kind == elfscope::BinaryKind::executable);
    CHECK(!bad.pie);
    CHECK(!bad.nx);
    CHECK(bad.executable_stack);
    CHECK(bad.relro == elfscope::RelroLevel::none);
    CHECK(!bad.canary);
    CHECK(mentions(bad, "executable"));
    CHECK(mentions(bad, "RELRO"));
    CHECK(mentions(bad, "stack protector"));

    const auto rpath = elfscope::analyze_security(ELFSCOPE_SAMPLE_RPATH);

    CHECK(!rpath.rpath.empty());
    CHECK(mentions(rpath, "RPATH"));
    CHECK(mentions(rpath, "relative"));

    const auto object = elfscope::analyze_security(ELFSCOPE_SAMPLE_OBJECT);

    CHECK(!object.linked);
    CHECK(object.kind == elfscope::BinaryKind::relocatable);
    CHECK(object.findings.empty());

    CHECK(elfscope::relro_name(elfscope::RelroLevel::partial) == "partial");

    return test::finish("security_tests");
}
