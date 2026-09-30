#include "elfscope/logger.hpp"

#include <iostream>
#include <mutex>

namespace {

elfscope::LogLevel current_level = elfscope::LogLevel::warning;
std::mutex log_mutex;

const char* level_name(elfscope::LogLevel level)
{
    switch (level) {
    case elfscope::LogLevel::debug:
        return "debug";
    case elfscope::LogLevel::info:
        return "info";
    case elfscope::LogLevel::warning:
        return "warning";
    case elfscope::LogLevel::error:
        return "error";
    }

    return "unknown";
}

}

namespace elfscope {

void set_log_level(LogLevel level)
{
    std::lock_guard<std::mutex> lock(log_mutex);
    current_level = level;
}

LogLevel log_level()
{
    std::lock_guard<std::mutex> lock(log_mutex);
    return current_level;
}

void log(LogLevel level, const std::string& message)
{
    std::lock_guard<std::mutex> lock(log_mutex);

    if (static_cast<int>(level) < static_cast<int>(current_level)) {
        return;
    }

    std::cerr
        << "["
        << level_name(level)
        << "] "
        << message
        << '\n';
}

void debug(const std::string& message)
{
    log(LogLevel::debug, message);
}

void info(const std::string& message)
{
    log(LogLevel::info, message);
}

void warning(const std::string& message)
{
    log(LogLevel::warning, message);
}

void error(const std::string& message)
{
    log(LogLevel::error, message);
}

}
