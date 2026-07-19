#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "core/units/u256.hpp"

namespace izan::codec {

// Recursive length prefix, encoder only — the wallet builds
// transactions, it never trusts incoming RLP enough to parse it.
// Items compose: rlp_bytes / rlp_uint produce encoded items,
// rlp_list wraps a sequence of already-encoded items.

// Byte string: single byte < 0x80 is itself; otherwise 0x80+len or
// 0xb7+lenlen header.
std::vector<uint8_t> rlp_bytes(std::span<const uint8_t> payload);

// Unsigned integer: minimal big-endian byte string, zero encodes as
// the empty string (0x80).
std::vector<uint8_t> rlp_uint(uint64_t value);
std::vector<uint8_t> rlp_uint(const units::U256& value);

// List of already-encoded items: 0xc0+len or 0xf7+lenlen header.
std::vector<uint8_t> rlp_list(std::span<const std::vector<uint8_t>> items);

}
