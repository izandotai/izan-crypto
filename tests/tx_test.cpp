#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

extern "C" {
#include <ecdsa.h>
#include <secp256k1.h>
}

#include "core/codec/rlp.hpp"
#include "core/crypto/eth.hpp"
#include "core/units/u256.hpp"
#include "domain/tx/eip1559.hpp"

#include "data/eip1559_vector.inc"

using izan::units::U256;

namespace {

std::vector<uint8_t> unhex(std::string_view hex)
{
    auto nib = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9')
            return uint8_t(c - '0');
        if (c >= 'a' && c <= 'f')
            return uint8_t(c - 'a' + 10);
        REQUIRE(false);
        return 0;
    };
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(uint8_t(nib(hex[i]) << 4 | nib(hex[i + 1])));
    return out;
}

std::string tohex(std::span<const uint8_t> bytes)
{
    static constexpr char d[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : bytes) {
        out += d[b >> 4];
        out += d[b & 0xf];
    }
    return out;
}

}

TEST_CASE("rlp: the canonical spec vectors")
{
    using izan::codec::rlp_bytes;
    using izan::codec::rlp_list;
    using izan::codec::rlp_uint;

    CHECK(tohex(rlp_bytes({})) == "80"); // empty string
    const uint8_t dog[] = { 'd', 'o', 'g' };
    CHECK(tohex(rlp_bytes(dog)) == "83646f67");
    const uint8_t zero_byte[] = { 0x00 };
    CHECK(tohex(rlp_bytes(zero_byte)) == "00"); // single byte < 0x80
    CHECK(tohex(rlp_uint(uint64_t(0))) == "80");
    CHECK(tohex(rlp_uint(uint64_t(15))) == "0f");
    CHECK(tohex(rlp_uint(uint64_t(1024))) == "820400");

    std::vector<std::vector<uint8_t>> catdog;
    const uint8_t cat[] = { 'c', 'a', 't' };
    catdog.push_back(rlp_bytes(cat));
    catdog.push_back(rlp_bytes(dog));
    CHECK(tohex(rlp_list(catdog)) == "c88363617483646f67");
    const std::vector<std::vector<uint8_t>> empty;
    CHECK(tohex(rlp_list(empty)) == "c0");

    // 56 bytes crosses into the long-string header form.
    std::vector<uint8_t> long_str(56, 'a');
    const std::string enc = tohex(rlp_bytes(long_str));
    CHECK(enc.substr(0, 4) == "b838");
    CHECK(enc.size() == 4 + 56 * 2);

    // U256 integers strip leading zeros down to the minimal form.
    CHECK(tohex(rlp_uint(U256::from_hex("0x0"))) == "80");
    CHECK(tohex(rlp_uint(U256::from_hex("0x400"))) == "820400");
}

TEST_CASE("eip1559: re-encoding a confirmed mainnet tx reproduces its hash")
{
    izan::tx::Eip1559Tx tx;
    tx.chain_id = kVecChainId;
    tx.nonce = kVecNonce;
    tx.max_priority_fee_per_gas = U256::from_hex(kVecMaxPriorityFee);
    tx.max_fee_per_gas = U256::from_hex(kVecMaxFee);
    tx.gas_limit = kVecGas;
    const std::vector<uint8_t> to = unhex(kVecTo);
    REQUIRE(to.size() == 20);
    std::memcpy(tx.to.data(), to.data(), 20);
    tx.value = U256::from_hex(kVecValue);

    const std::vector<uint8_t> payload = izan::tx::signing_payload(tx);
    REQUIRE(!payload.empty());
    CHECK(payload[0] == 0x02);

    std::array<uint8_t, 32> r {}, s {};
    const std::vector<uint8_t> rb = unhex(kVecR);
    const std::vector<uint8_t> sb = unhex(kVecS);
    REQUIRE(rb.size() == 32);
    REQUIRE(sb.size() == 32);
    std::memcpy(r.data(), rb.data(), 32);
    std::memcpy(s.data(), sb.data(), 32);

    const std::vector<uint8_t> raw
        = izan::tx::encode_signed(tx, kVecYParity, r, s);
    CHECK(tohex(izan::tx::tx_hash(raw)) == kVecHash);
}

TEST_CASE("eip1559: sign, recover, and land on the signer's address")
{
    // Hardhat account #0 — a published development key, never funds.
    const std::vector<uint8_t> priv = unhex(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    REQUIRE(priv.size() == 32);

    izan::tx::Eip1559Tx tx;
    tx.chain_id = 1;
    tx.nonce = 7;
    tx.max_priority_fee_per_gas = U256::from_dec("1000000000");
    tx.max_fee_per_gas = U256::from_dec("30000000000");
    tx.gas_limit = 21000;
    const std::vector<uint8_t> to
        = unhex("6b2c6eaac28a749fe950c4ea9d9e56c16b63bce1");
    std::memcpy(tx.to.data(), to.data(), 20);
    tx.value = U256::from_dec("1000000000000000000");

    const std::array<uint8_t, 32> digest = izan::tx::signing_hash(tx);
    uint8_t sig[64];
    uint8_t parity = 0;
    REQUIRE(ecdsa_sign_digest(
                &secp256k1, priv.data(), digest.data(), sig, &parity, nullptr)
        == 0);

    uint8_t pub[65];
    REQUIRE(
        ecdsa_recover_pub_from_sig(&secp256k1, pub, sig, digest.data(), parity)
        == 0);
    CHECK(izan::crypto::eth_address(std::span<const uint8_t, 65>(pub, 65))
        == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
}
