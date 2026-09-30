#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace elfscope {

enum class RelroLevel {
    none,
    partial,
    full
};

enum class BinaryKind {
    executable,
    pie_executable,
    shared_object,
    relocatable,
    core,
    other
};

struct SecurityReport {
    std::string path;
    BinaryKind kind = BinaryKind::other;

    // false for .o files and cores, hardening flags mean nothing there
    bool linked = false;
    bool dynamically_linked = false;

    bool pie = false;
    bool nx = false;
    bool executable_stack = false;
    bool writable_executable = false;
    RelroLevel relro = RelroLevel::none;

    bool canary = false;
    bool fortify = false;
    std::size_t fortified_calls = 0;

    bool stripped = false;
    bool textrel = false;

    std::string rpath;
    std::string runpath;

    std::vector<std::string> findings;
};

SecurityReport analyze_security(const std::string& path);

std::string relro_name(RelroLevel level);
std::string binary_kind_name(BinaryKind kind);

}
