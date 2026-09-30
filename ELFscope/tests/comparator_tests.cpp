#include "check.hpp"

#include "elfscope/file_comparator.hpp"

int main()
{
    const auto same = elfscope::compare_files(
        ELFSCOPE_SAMPLE_HARDENED,
        ELFSCOPE_SAMPLE_HARDENED);

    CHECK(same.same_bytes);
    CHECK(same.same_size);
    CHECK(same.same_class);
    CHECK(same.same_machine);
    CHECK(same.same_type);
    CHECK(same.same_entry);
    CHECK(same.same_sections);
    CHECK(same.same_segments);
    CHECK(same.same_symbols);
    CHECK(same.same_dependencies);
    CHECK(same.differences.empty());

    // flip the very last byte, only the raw bytes should notice
    auto bytes = test::slurp(ELFSCOPE_SAMPLE_HARDENED);
    CHECK(!bytes.empty());
    bytes.back() ^= 0xff;

    test::TempFile copy("copy");
    copy.write(bytes);

    const auto changed = elfscope::compare_files(
        ELFSCOPE_SAMPLE_HARDENED,
        copy.path());

    CHECK(changed.same_size);
    CHECK(!changed.same_bytes);
    CHECK(!changed.differences.empty());

    const auto different = elfscope::compare_files(
        ELFSCOPE_SAMPLE_HARDENED,
        ELFSCOPE_SAMPLE_WEAK);

    CHECK(!different.same_bytes);
    CHECK(!different.same_type);

    return test::finish("comparator_tests");
}
