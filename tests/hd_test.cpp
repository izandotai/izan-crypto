#include <doctest/doctest.h>

#include <cstdint>
#include <string_view>
#include <vector>

#include "core/crypto/hd.hpp"

#include "data/bip32_vectors.inc"

namespace {

std::vector<uint8_t> unhex(std::string_view hex)
{
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        const auto nibble = [&](char c) -> uint8_t {
            return c <= '9' ? c - '0' : c - 'a' + 10;
        };
        out[i] = nibble(hex[2 * i]) << 4 | nibble(hex[2 * i + 1]);
    }
    return out;
}

}

TEST_CASE("BIP-32 official vectors: seed → derivation chain → xprv/xpub")
{
    for (const auto& v : kBip32Vectors) {
        CAPTURE(v.path);
        const auto seed = unhex(v.seed_hex);
        const auto root = izan::crypto::HdKey::from_seed(seed);
        REQUIRE(root);
        const auto key = root->derive(v.path);
        REQUIRE(key);
        CHECK(key->xprv() == v.xprv);
        CHECK(key->xpub() == v.xpub);
    }
}

TEST_CASE("BIP-32 path parsing rejects garbage")
{
    const auto root = izan::crypto::HdKey::from_seed(
        unhex("000102030405060708090a0b0c0d0e0f"));
    REQUIRE(root);
    CHECK(!root->derive("m/abc"));
    CHECK(!root->derive("m//0"));
    CHECK(!root->derive("m/2147483648")); // ≥ 2^31 needs the hardened marker
    CHECK(root->derive("m/44'/60'/0'/0/0"));
    CHECK(root->derive("0h/1"));          // relative, h-style hardened
}
