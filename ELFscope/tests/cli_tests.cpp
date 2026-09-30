#include "check.hpp"

#include "elfscope/argument_parser.hpp"
#include "elfscope/command_handler.hpp"

#include <sstream>
#include <string>
#include <vector>

namespace {

elfscope::Arguments parse(const std::vector<std::string>& args)
{
    return elfscope::ArgumentParser().parse(args);
}

int run(
    const std::vector<std::string>& args,
    std::string& out,
    std::string& err)
{
    std::ostringstream out_stream;
    std::ostringstream err_stream;

    const int code = elfscope::CommandHandler().execute(
        parse(args),
        out_stream,
        err_stream);

    out = out_stream.str();
    err = err_stream.str();
    return code;
}

}

int main()
{
    // argument parsing
    CHECK(parse({"info", "file"}).valid);
    CHECK(parse({"-v", "info", "file"}).verbose);
    CHECK(parse({"info", "file", "--verbose"}).verbose);
    CHECK(parse({"--help"}).help);
    CHECK(parse({"-V"}).version);
    CHECK(parse({"compare", "a", "b"}).second_path == "b");
    CHECK(parse({"--", "info", "-weird-name"}).path == "-weird-name");

    CHECK(!parse({}).valid);
    CHECK(!parse({"info"}).valid);
    CHECK(!parse({"info", "a", "b"}).valid);
    CHECK(!parse({"compare", "a"}).valid);
    CHECK(!parse({"bogus", "a"}).valid);
    CHECK(!parse({"--nope", "info", "a"}).valid);
    CHECK(!parse({"--nope", "info", "a"}).error.empty());

    // command handler
    std::string out;
    std::string err;

    CHECK(run({"--version"}, out, err) == 0);
    CHECK(out.find("elfscope") != std::string::npos);

    CHECK(run({"--help"}, out, err) == 0);
    CHECK(out.find("usage:") != std::string::npos);

    CHECK(run({"bogus", "x"}, out, err) == 2);
    CHECK(err.find("unknown command") != std::string::npos);

    CHECK(run({"info", "/definitely/not/here"}, out, err) == 1);
    CHECK(err.find("can't open") != std::string::npos);

    for (const char* command : {"info", "sections", "segments", "mapping",
                                "dynamic", "relocations", "symbols",
                                "dependencies", "security", "stats"}) {
        CHECK(run({command, ELFSCOPE_SAMPLE_HARDENED}, out, err) == 0);
        CHECK(!out.empty());
        CHECK(err.empty());
    }

    CHECK(run({"info", ELFSCOPE_SAMPLE_HARDENED}, out, err) == 0);
    CHECK(out.find("class: ELF64") != std::string::npos ||
          out.find("class: ELF32") != std::string::npos);
    CHECK(out.find("interpreter: /") != std::string::npos);

    CHECK(run({"all", ELFSCOPE_SAMPLE_HARDENED}, out, err) == 0);
    CHECK(out.find("section to segment mapping") != std::string::npos);
    CHECK(out.find("security:") != std::string::npos);

    CHECK(run({"all", ELFSCOPE_SAMPLE_OBJECT}, out, err) == 0);

    CHECK(run({"compare", ELFSCOPE_SAMPLE_HARDENED, ELFSCOPE_SAMPLE_HARDENED},
              out, err) == 0);
    CHECK(out.find("no differences") != std::string::npos);

    CHECK(run({"compare", ELFSCOPE_SAMPLE_HARDENED, ELFSCOPE_SAMPLE_WEAK},
              out, err) == 0);
    CHECK(out.find("differences:") != std::string::npos);

    return test::finish("cli_tests");
}
