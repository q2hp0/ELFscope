#pragma once

#include "elf_file.hpp"
#include "section.hpp"
#include "segment.hpp"
#include "symbol.hpp"

#include <string>
#include <vector>

namespace elfscope {

class ElfParser {
public:
    ElfParser() = default;

    ElfFile parse(const std::string& path) const;
    std::vector<Section> sections(const std::string& path) const;
    std::vector<Segment> segments(const std::string& path) const;
    std::string interpreter(const std::string& path) const;
    std::vector<Symbol> symbols(const std::string& path) const;

private:
    static void check_magic(const unsigned char* ident, const std::string& path);
};

}
