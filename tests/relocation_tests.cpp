#include "check.hpp"

#include "elfscope/relocation.hpp"

int main()
{
    const auto relocations = elfscope::read_relocations("/proc/self/exe");

    CHECK(!relocations.empty());

    for (const auto& relocation : relocations) {
        CHECK(!relocation.table.empty());
        CHECK(!relocation.type_name.empty());
    }

#if defined(__x86_64__)
    bool jump_slot = false;
    bool relative = false;

    for (const auto& relocation : relocations) {
        jump_slot = jump_slot || relocation.type_name == "R_X86_64_JUMP_SLOT";
        relative = relative || relocation.type_name == "R_X86_64_RELATIVE";
    }

    CHECK(jump_slot);
    CHECK(relative);
#endif

    CHECK(elfscope::read_relocations(ELFSCOPE_SAMPLE_OBJECT).empty());

    return test::finish("relocation_tests");
}
