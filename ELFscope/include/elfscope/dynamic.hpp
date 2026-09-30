#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace elfscope {

struct DynamicInfo {
    std::vector<std::string> needed;
    std::string soname;
    std::string rpath;
    std::string runpath;

    std::uint64_t flags = 0;
    std::uint64_t flags_1 = 0;

    std::uint64_t plt_got = 0;
    std::uint64_t plt_relocation_size = 0;

    std::uint64_t rela = 0;
    std::uint64_t rela_size = 0;
    std::uint64_t rela_entry_size = 0;

    std::uint64_t rel = 0;
    std::uint64_t rel_size = 0;
    std::uint64_t rel_entry_size = 0;

    std::uint64_t plt_rel_type = 0;
    std::uint64_t jmprel = 0;
    std::uint64_t hash = 0;
    std::uint64_t gnu_hash = 0;

    std::uint64_t init = 0;
    std::uint64_t fini = 0;
    std::uint64_t init_array = 0;
    std::uint64_t init_array_size = 0;
    std::uint64_t fini_array = 0;
    std::uint64_t fini_array_size = 0;

    std::uint64_t entry_count = 0;
};

DynamicInfo read_dynamic_info(const std::string& path);

std::string dynamic_flags_name(std::uint64_t flags);
std::string dynamic_flags_1_name(std::uint64_t flags);

}
