#pragma once

#include <stdexcept>
#include <string>

namespace elfscope {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

class FileError : public Error {
public:
    explicit FileError(const std::string& message) : Error(message) {}
};

class FormatError : public Error {
public:
    explicit FormatError(const std::string& message) : Error(message) {}
};

class BoundsError : public FormatError {
public:
    explicit BoundsError(const std::string& message) : FormatError(message) {}
};

}
