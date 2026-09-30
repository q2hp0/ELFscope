#include "elfscope/file_reader.hpp"
#include "elfscope/errors.hpp"

#include <fstream>
#include <limits>

namespace elfscope {

FileReader::FileReader(const std::string& path)
    : path_(path)
{
    std::ifstream input(path, std::ios::binary | std::ios::ate);

    if (!input) {
        throw FileError("cannot open file: " + path);
    }

    const auto end = input.tellg();

    if (end < 0) {
        throw FileError("cannot determine file size: " + path);
    }

    const auto size = static_cast<std::uint64_t>(end);

    if (size > std::numeric_limits<std::size_t>::max()) {
        throw FileError("file is too large: " + path);
    }

    data_.resize(static_cast<std::size_t>(size));

    input.seekg(0);

    if (!data_.empty() &&
        !input.read(
            reinterpret_cast<char*>(data_.data()),
            static_cast<std::streamsize>(data_.size()))) {
        throw FileError("cannot read file: " + path);
    }
}

std::size_t FileReader::size() const noexcept
{
    return data_.size();
}

const std::vector<std::uint8_t>& FileReader::data() const noexcept
{
    return data_;
}

void FileReader::require_range(
    std::size_t offset,
    std::size_t size) const
{
    if (offset > data_.size() ||
        size > data_.size() - offset) {
        throw BoundsError("file range is outside file: " + path_);
    }
}

std::uint8_t FileReader::u8(std::size_t offset) const
{
    require_range(offset, 1);
    return data_[offset];
}

std::uint16_t FileReader::u16le(std::size_t offset) const
{
    require_range(offset, 2);

    return static_cast<std::uint16_t>(
        data_[offset] |
        (static_cast<std::uint16_t>(data_[offset + 1]) << 8));
}

std::uint32_t FileReader::u32le(std::size_t offset) const
{
    require_range(offset, 4);

    return static_cast<std::uint32_t>(
        data_[offset] |
        (static_cast<std::uint32_t>(data_[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(data_[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(data_[offset + 3]) << 24));
}

std::uint64_t FileReader::u64le(std::size_t offset) const
{
    require_range(offset, 8);

    std::uint64_t value = 0;

    for (unsigned int i = 0; i < 8; ++i) {
        value |=
            static_cast<std::uint64_t>(data_[offset + i]) <<
            (i * 8);
    }

    return value;
}

std::string FileReader::string_at(
    std::size_t offset,
    std::size_t maximum) const
{
    require_range(offset, 0);

    const auto available = data_.size() - offset;
    const auto limit = maximum < available ? maximum : available;

    std::size_t length = 0;

    while (length < limit && data_[offset + length] != 0) {
        ++length;
    }

    if (length == limit && limit < maximum) {
        throw BoundsError("unterminated string in file: " + path_);
    }

    return std::string(
        reinterpret_cast<const char*>(data_.data() + offset),
        length);
}

}
