#pragma once

#include <string>

namespace elfscope {

enum class LogLevel {
    debug,
    info,
    warning,
    error
};

void set_log_level(LogLevel level);
LogLevel log_level();

void log(LogLevel level, const std::string& message);
void debug(const std::string& message);
void info(const std::string& message);
void warning(const std::string& message);
void error(const std::string& message);

}
