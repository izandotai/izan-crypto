#include "core/crypto/eip712.hpp"

extern "C" {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvolatile"
#include <sha3.h>
#pragma GCC diagnostic pop
}

namespace izan::crypto::eip712 {

Hash32 keccak256(std::span<const uint8_t> bytes)
{
    Hash32 out;
    keccak_256(bytes.data(), bytes.size(), out.data());
    return out;
}

Hash32 keccak256(std::string_view text)
{
    return keccak256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

void append_word(std::vector<uint8_t>& buf, const Hash32& h)
{
    buf.insert(buf.end(), h.begin(), h.end());
}

void append_u256(std::vector<uint8_t>& buf, const units::U256& v)
{
    buf.insert(buf.end(), v.be.begin(), v.be.end());
}

void append_u64(std::vector<uint8_t>& buf, uint64_t v)
{
    append_u256(buf, units::U256::from_u64(v));
}

void append_address(std::vector<uint8_t>& buf, const EthAddress& a)
{
    buf.insert(buf.end(), 12, 0);
    buf.insert(buf.end(), a.begin(), a.end());
}

void append_u8(std::vector<uint8_t>& buf, uint8_t v)
{
    buf.insert(buf.end(), 31, 0);
    buf.push_back(v);
}

Hash32 domain_separator(std::string_view name, std::string_view version,
    uint64_t chain_id, std::optional<EthAddress> verifying_contract)
{
    static const Hash32 kTypeHash = keccak256(
        std::string_view("EIP712Domain(string name,string version,uint256 "
                         "chainId,address verifyingContract)"));
    std::vector<uint8_t> buf;
    buf.reserve(5 * 32);
    append_word(buf, kTypeHash);
    append_word(buf, keccak256(name));
    append_word(buf, keccak256(version));
    append_u64(buf, chain_id);
    append_address(buf, verifying_contract.value_or(EthAddress {}));
    return keccak256(buf);
}

Hash32 domain_separator_nvc(
    std::string_view name, std::string_view version, uint64_t chain_id)
{
    static const Hash32 kTypeHash = keccak256(std::string_view(
        "EIP712Domain(string name,string version,uint256 chainId)"));
    std::vector<uint8_t> buf;
    buf.reserve(4 * 32);
    append_word(buf, kTypeHash);
    append_word(buf, keccak256(name));
    append_word(buf, keccak256(version));
    append_u64(buf, chain_id);
    return keccak256(buf);
}

Hash32 typed_digest(const Hash32& domain_sep, const Hash32& struct_hash)
{
    std::vector<uint8_t> buf;
    buf.reserve(2 + 64);
    buf.push_back(0x19);
    buf.push_back(0x01);
    append_word(buf, domain_sep);
    append_word(buf, struct_hash);
    return keccak256(buf);
}

}
