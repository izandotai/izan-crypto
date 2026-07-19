#include "core/codec/rlp.hpp"

namespace izan::codec {

namespace {

    // Header for a payload of `size` bytes: `base` is 0x80 for strings
    // and 0xc0 for lists.
    std::vector<uint8_t> length_header(std::size_t size, uint8_t base)
    {
        std::vector<uint8_t> out;
        if (size <= 55) {
            out.push_back(uint8_t(base + size));
            return out;
        }
        uint8_t len_be[8];
        int n = 0;
        for (std::size_t v = size; v; v >>= 8)
            len_be[n++] = uint8_t(v & 0xff);
        out.push_back(uint8_t(base + 55 + n));
        for (int i = n - 1; i >= 0; --i)
            out.push_back(len_be[i]);
        return out;
    }

}

std::vector<uint8_t> rlp_bytes(std::span<const uint8_t> payload)
{
    if (payload.size() == 1 && payload[0] < 0x80)
        return { payload[0] };
    std::vector<uint8_t> out = length_header(payload.size(), 0x80);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<uint8_t> rlp_uint(uint64_t value)
{
    uint8_t be[8];
    int n = 0;
    for (uint64_t v = value; v; v >>= 8)
        be[n++] = uint8_t(v & 0xff);
    std::vector<uint8_t> minimal;
    for (int i = n - 1; i >= 0; --i)
        minimal.push_back(be[i]);
    return rlp_bytes(minimal);
}

std::vector<uint8_t> rlp_uint(const units::U256& value)
{
    std::size_t first = 0;
    while (first < 32 && value.be[first] == 0)
        ++first;
    return rlp_bytes(std::span(value.be).subspan(first));
}

std::vector<uint8_t> rlp_list(std::span<const std::vector<uint8_t>> items)
{
    std::size_t total = 0;
    for (const auto& item : items)
        total += item.size();
    std::vector<uint8_t> out = length_header(total, 0xc0);
    out.reserve(out.size() + total);
    for (const auto& item : items)
        out.insert(out.end(), item.begin(), item.end());
    return out;
}

}
