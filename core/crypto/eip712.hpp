#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "core/units/u256.hpp"

namespace izan::crypto::eip712 {

// EIP-712 structured signing, the word-at-a-time way: callers build a
// struct hash from 32-byte words with the append helpers, then bind it
// to a domain. No type reflection, no JSON — a signing plane wants the
// bytes explicit.

using Hash32 = std::array<uint8_t, 32>;
using EthAddress = std::array<uint8_t, 20>;

Hash32 keccak256(std::span<const uint8_t> bytes);
Hash32 keccak256(std::string_view text);

// EIP712Domain(string name,string version,uint256 chainId,address
// verifyingContract). A nullopt contract encodes as the zero address.
Hash32 domain_separator(std::string_view name, std::string_view version,
    uint64_t chain_id, std::optional<EthAddress> verifying_contract);

// The three-field domain, no verifyingContract — some venues (e.g.
// exchange auth schemes) bind to name/version/chain alone.
Hash32 domain_separator_nvc(
    std::string_view name, std::string_view version, uint64_t chain_id);

// keccak256(0x19 || 0x01 || domainSeparator || structHash) — the
// digest an EIP-712 signature actually covers.
Hash32 typed_digest(const Hash32& domain_sep, const Hash32& struct_hash);

// ABI word encoding: each helper appends exactly 32 bytes.
void append_word(std::vector<uint8_t>& buf, const Hash32& h);
void append_u256(std::vector<uint8_t>& buf, const units::U256& v);
void append_u64(std::vector<uint8_t>& buf, uint64_t v);
void append_address(std::vector<uint8_t>& buf, const EthAddress& a);
void append_u8(std::vector<uint8_t>& buf, uint8_t v);

}
