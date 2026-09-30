#include "check.hpp"

#include "elfscope/elf_parser.hpp"
#include "elfscope/errors.hpp"

int main()
{
    elfscope::ElfParser parser;
    const auto elf = parser.parse("/proc/self/exe");

    CHECK(elf.elf_class == (sizeof(void*) == 8
        ? elfscope::ElfClass::elf64
        : elfscope::ElfClass::elf32));
    CHECK(elf.endianness == elfscope::Endianness::little);
    CHECK(elf.machine != 0);
    CHECK(elf.program_header_count > 0);
    CHECK(elf.section_header_count > 0);
    CHECK(!parser.interpreter("/proc/self/exe").empty());

    CHECK_THROWS_AS(
        parser.parse("/definitely/not/here"),
        elfscope::FileError);

    test::TempFile garbage("garbage");
    garbage.write({'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd',
                   '!', '!', '!', '!', '!', '!', '!', '!', '!'});
    CHECK_THROWS_AS(parser.parse(garbage.path()), elfscope::FormatError);

    test::TempFile tiny("tiny");
    tiny.write({0x7f, 'E', 'L', 'F'});
    CHECK_THROWS_AS(parser.parse(tiny.path()), elfscope::Error);

    test::TempFile empty("empty");
    empty.write({});
    CHECK_THROWS_AS(parser.parse(empty.path()), elfscope::Error);

    return test::finish("parser_tests");
}
