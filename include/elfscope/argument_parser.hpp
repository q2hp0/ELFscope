#pragma once

#include <string>
#include <vector>

namespace elfscope {

struct Arguments {
    std::string command;
    std::string path;
    std::string second_path;

    bool help = false;
    bool version = false;
    bool verbose = false;
    bool valid = false;

    // filled when valid is false and there is something to tell the user
    std::string error;
};

class ArgumentParser {
public:
    Arguments parse(int argc, char** argv) const;
    Arguments parse(const std::vector<std::string>& args) const;
};

bool is_known_command(const std::string& command);
std::string usage_text();

}
