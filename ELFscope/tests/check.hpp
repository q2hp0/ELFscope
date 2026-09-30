#pragma once

// asserts vanish with NDEBUG and release is the default build type here,
// so tests use this instead of <cassert>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include <unistd.h>

namespace test {

inline int& failures()
{
    static int count = 0;
    return count;
}

inline int finish(const char* name)
{
    if (failures() != 0) {
        std::cerr << name << ": " << failures() << " check(s) failed\n";
        return 1;
    }

    std::cout << name << ": ok\n";
    return 0;
}

// removes the file when it goes out of scope
class TempFile {
public:
    explicit TempFile(const std::string& tag)
    {
        static int counter = 0;

        path_ = std::filesystem::temp_directory_path() /
            ("elfscope_" + tag + "_" + std::to_string(::getpid()) +
             "_" + std::to_string(counter++));
    }

    ~TempFile()
    {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    std::string path() const { return path_.string(); }

    void write(const std::vector<unsigned char>& bytes) const
    {
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        out.write(
            reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    }

private:
    std::filesystem::path path_;
};

inline std::vector<unsigned char> slurp(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);

    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>());
}

}

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::cerr << __FILE__ << ':' << __LINE__                      \
                      << ": check failed: " #expr "\n";                   \
            ++test::failures();                                           \
        }                                                                 \
    } while (0)

#define CHECK_THROWS_AS(expr, type)                                       \
    do {                                                                  \
        bool caught_ = false;                                             \
        try {                                                             \
            (void)(expr);                                                 \
        } catch (const type&) {                                           \
            caught_ = true;                                               \
        } catch (...) {                                                   \
        }                                                                 \
        if (!caught_) {                                                   \
            std::cerr << __FILE__ << ':' << __LINE__                      \
                      << ": expected " #type " from: " #expr "\n";        \
            ++test::failures();                                           \
        }                                                                 \
    } while (0)

// fixtures compiled by cmake from examples/sample.c
#ifndef ELFSCOPE_SAMPLE_HARDENED
#define ELFSCOPE_SAMPLE_HARDENED "/proc/self/exe"
#endif
#ifndef ELFSCOPE_SAMPLE_WEAK
#define ELFSCOPE_SAMPLE_WEAK "/proc/self/exe"
#endif
#ifndef ELFSCOPE_SAMPLE_RPATH
#define ELFSCOPE_SAMPLE_RPATH "/proc/self/exe"
#endif
#ifndef ELFSCOPE_SAMPLE_OBJECT
#define ELFSCOPE_SAMPLE_OBJECT "/proc/self/exe"
#endif
