#pragma once

#include <string>
#include <vector>

namespace elfscope {

struct Dependency {
    std::string name;
};

std::vector<Dependency> read_dependencies(const std::string& path);

}
