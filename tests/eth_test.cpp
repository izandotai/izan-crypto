#include <doctest/doctest.h>

#include <array>
#include <cstring>
#include <string>

extern "C" {
#include <ecdsa.h>
#include <secp256k1.h>
}

#include "core/crypto/bip39.hpp"
#include "core/crypto/eth.hpp"
#include "core/crypto/hd.hpp"
#include "core/crypto/secp256k1_key.hpp"

#include "data/eip55_vectors.inc"

TEST_CASE("EIP-55 spec addresses are checksum fixed points")
{
    for (const char* addr : kEip55Vectors) {
        CAPTURE(addr);
        std::string lower(addr);
        for (char& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        CHECK(izan::crypto::eth_checksum_address(lower) == addr);
    }
}

TEST_CASE("EIP-55 rejects malformed input")
{
    CHECK(izan::crypto::eth_checksum_address("0x1234").empty());
    CHECK(izan::crypto::eth_checksum_address(
        "zz08400098527886E0F7030069857D2E4169EE7X")
            .empty());
}

TEST_CASE("mnemonic → m/44'/60'/0'/0/0 → well-known address")
{
    // Hardhat/Anvil default account #0 — the most widely cross-checked
    // mnemonic→address pair in the EVM ecosystem.
    const auto seed = izan::crypto::mnemonic_to_seed(
        "test test test test test test test test test test test junk", "");
    const auto root = izan::crypto::HdKey::from_seed(seed);
    REQUIRE(root);
    const auto key = root->derive("m/44'/60'/0'/0/0");
    REQUIRE(key);
    CHECK(izan::crypto::eth_address(key->public_key_uncompressed())
        == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
}

TEST_CASE("sign_digest recovers to the signing key and keeps s low")
{
    const auto seed = izan::crypto::mnemonic_to_seed(
        "test test test test test test test test test test test junk", "");
    const auto root = izan::crypto::HdKey::from_seed(seed);
    REQUIRE(root);
    const auto key = root->derive("m/44'/60'/0'/0/0");
    REQUIRE(key);

    std::array<uint8_t, 32> digest {};
    digest.fill(0x5a);
    const auto sig = key->sign_digest(digest);
    REQUIRE(sig);

    // Ethereum consensus rejects high-s signatures outright (EIP-2):
    // s must stay below half the curve order, so its top byte is small.
    CHECK(sig->s[0] < 0x80);
    CHECK(sig->y_parity <= 1);

    uint8_t rs[64];
    std::memcpy(rs, sig->r.data(), 32);
    std::memcpy(rs + 32, sig->s.data(), 32);
    uint8_t pub[65];
    REQUIRE(ecdsa_recover_pub_from_sig(
                &secp256k1, pub, rs, digest.data(), sig->y_parity)
        == 0);
    CHECK(izan::crypto::eth_address(std::span<const uint8_t, 65>(pub, 65))
        == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
}

TEST_CASE("raw secp256k1 key matches Ethereum address and signature vectors")
{
    std::array<uint8_t, 32> scalar {};
    scalar.back() = 1;
    auto key = izan::crypto::Secp256k1PrivateKey::from_bytes(scalar);
    REQUIRE(key);
    CHECK(izan::crypto::eth_address(key->public_key_uncompressed())
        == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");

    constexpr std::array<uint8_t, 32> digest {
        0xf4, 0xfb, 0x49, 0xf1, 0xa3, 0x7c, 0x5f, 0x2b,
        0x37, 0x00, 0x08, 0x92, 0x9b, 0x40, 0xd0, 0x65,
        0xb2, 0xcf, 0x21, 0xed, 0x68, 0x22, 0xd5, 0xd8,
        0xec, 0xa3, 0x20, 0x73, 0x90, 0x5e, 0xcb, 0x6d,
    };
    const auto signature = key->sign_digest(digest);
    REQUIRE(signature);
    CHECK(signature->r
        == std::array<uint8_t, 32> {
            0x8e, 0xca, 0x05, 0x78, 0x6b, 0xc5, 0x62, 0xa6,
            0x83, 0x3e, 0x06, 0x58, 0xfb, 0xd8, 0x24, 0x49,
            0x8a, 0xda, 0x3b, 0xeb, 0xa3, 0x4f, 0xc3, 0xbf,
            0x63, 0xb8, 0xdd, 0x4d, 0x04, 0xdc, 0x60, 0x48,
        });
    CHECK(signature->s
        == std::array<uint8_t, 32> {
            0x67, 0xf7, 0x0f, 0xa2, 0x70, 0x72, 0xa5, 0x6c,
            0xea, 0x9a, 0x2a, 0x37, 0xd0, 0x0d, 0xf4, 0x7d,
            0xc5, 0xc7, 0x80, 0xb8, 0x67, 0xe5, 0x1b, 0x61,
            0x5c, 0x83, 0x26, 0xcf, 0x37, 0xef, 0x08, 0x46,
        });
    CHECK(signature->y_parity == 0);

    scalar.fill(0);
    CHECK_FALSE(izan::crypto::Secp256k1PrivateKey::from_bytes(scalar));
    scalar.fill(0xff);
    CHECK_FALSE(izan::crypto::Secp256k1PrivateKey::from_bytes(scalar));
}
