#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace elfscope {

class FileReader {
public:
    explicit FileReader(const std::string& path);

    std::size_t size() const noexcept;
    const std::vector<std::uint8_t>& data() const noexcept;

    void require_range(std::size_t offset, std::size_t size) const;

    std::uint8_t u8(std::size_t offset) const;
    std::uint16_t u16le(std::size_t offset) const;
    std::uint32_t u32le(std::size_t offset) const;
    std::uint64_t u64le(std::size_t offset) const;

    std::string string_at(std::size_t offset, std::size_t maximum) const;

private:
    std::string path_;
    std::vector<std::uint8_t> data_;
};

}
