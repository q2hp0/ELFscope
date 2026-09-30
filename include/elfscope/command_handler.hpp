#pragma once

#include "argument_parser.hpp"

#include <iostream>
#include <ostream>

namespace elfscope {

// exit codes: 0 fine, 1 the file could not be analyzed, 2 bad command line
class CommandHandler {
public:
    int execute(
        const Arguments& arguments,
        std::ostream& out = std::cout,
        std::ostream& err = std::cerr) const;
};

}
