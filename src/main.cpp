#include "elfscope/argument_parser.hpp"
#include "elfscope/command_handler.hpp"

int main(int argc, char** argv)
{
    elfscope::ArgumentParser parser;
    elfscope::CommandHandler handler;

    return handler.execute(parser.parse(argc, argv));
}
