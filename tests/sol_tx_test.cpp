// The Solana transaction grammar against its own vectors — moved home
// from the wallet's suite: compact-u16, the System transfer shapes
// (two-party and self), the SPL shapes (classic, Token-2022 and
// self), the ATA duel and RFC 8032.

#include <doctest/doctest.h>

#include <algorithm>
#include <span>
#include <string>
#include <vector>

extern "C" {
#include <base58.h>
}

#include "core/crypto/sol.hpp"
#include "domain/sol/sol_tx.hpp"

TEST_CASE("compact-u16 walks its boundaries both ways")
{
    auto enc = [](uint16_t v) {
        std::vector<uint8_t> out;
        izan::sol::put_compact_u16(out, v);
        return out;
    };
    CHECK(enc(0) == std::vector<uint8_t> { 0x00 });
    CHECK(enc(127) == std::vector<uint8_t> { 0x7f });
    CHECK(enc(128) == std::vector<uint8_t> { 0x80, 0x01 });
    CHECK(enc(16383) == std::vector<uint8_t> { 0xff, 0x7f });
    CHECK(enc(16384) == std::vector<uint8_t> { 0x80, 0x80, 0x01 });
    CHECK(enc(65535) == std::vector<uint8_t> { 0xff, 0xff, 0x03 });
    for (uint32_t v : { 0u, 127u, 128u, 16383u, 16384u, 65535u }) {
        const auto bytes = enc(uint16_t(v));
        std::size_t pos = 0;
        CHECK(izan::sol::take_compact_u16(bytes, pos) == v);
        CHECK(pos == bytes.size());
    }
    std::size_t pos = 0;
    CHECK_THROWS(izan::sol::take_compact_u16(
        std::vector<uint8_t> { 0x80, 0x80, 0x80, 0x01 }, pos));
}

TEST_CASE("a transfer message survives the round trip and nothing else passes")
{
    const char* alice = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    const char* bob = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    std::array<uint8_t, 32> hash {};
    for (int i = 0; i < 32; ++i)
        hash[std::size_t(i)] = uint8_t(i + 1);
    const auto msg
        = izan::sol::encode_transfer_message(alice, bob, 12345678, hash);
    // Fixed grammar: 3 header + 1 count + 96 keys + 32 hash + 1 count
    // + 1 idx + 1 count + 2 accounts + 1 len + 12 data.
    CHECK(msg.size() == 150);
    const auto back = izan::sol::parse_transfer_message(msg);
    CHECK(back.from == alice);
    CHECK(back.to == bob);
    CHECK(back.lamports == 12345678);
    CHECK(back.blockhash == hash);

    CHECK_THROWS(izan::sol::encode_transfer_message(alice, bob, 0, hash));
    CHECK_THROWS(izan::sol::encode_transfer_message("junk", bob, 1, hash));

    // The whitelist: every tampered shape must be refused.
    auto tamper = [&](std::size_t at, uint8_t v) {
        auto bad = msg;
        bad[at] = v;
        return bad;
    };
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(0, 2)));   // 2 sigs
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(3, 4)));   // 4 accts
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(70, 1)));  // program
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(132, 2))); // 2 instr
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(133, 1))); // prog idx
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(138, 1))); // tag
    auto truncated = msg;
    truncated.pop_back();
    CHECK_THROWS(izan::sol::parse_transfer_message(truncated));
    auto trailing = msg;
    trailing.push_back(0);
    CHECK_THROWS(izan::sol::parse_transfer_message(trailing));

    // signature || message, one signature slot.
    std::array<uint8_t, 64> sig {};
    sig[0] = 0xAA;
    const auto tx = izan::sol::assemble_tx(sig, msg);
    CHECK(tx.size() == 1 + 64 + msg.size());
    CHECK(tx[0] == 1);
    CHECK(tx[1] == 0xAA);
}

TEST_CASE("ed25519 signing matches RFC 8032 and its own public key")
{
    auto unhex = [](const char* h) {
        std::vector<uint8_t> out;
        for (const char* p = h; p[0] && p[1]; p += 2) {
            auto nib = [](char c) {
                return uint8_t(c <= '9' ? c - '0' : c - 'a' + 10);
            };
            out.push_back(uint8_t(nib(p[0]) << 4 | nib(p[1])));
        }
        return out;
    };
    // RFC 8032 §7.1 TEST 1: the empty message.
    std::array<uint8_t, 32> seed1 {};
    const auto s1 = unhex("9d61b19deffd5a60ba844af492ec2cc4"
                          "4449c5697b326919703bac031cae7f60");
    std::copy(s1.begin(), s1.end(), seed1.begin());
    const auto sig1 = izan::crypto::sol_sign(seed1, {});
    CHECK(std::vector<uint8_t>(sig1.begin(), sig1.end())
        == unhex("e5564300c360ac729086e2cc806e828a"
                 "84877f1eb8e5d974d873e06522490155"
                 "5fb8821590a33bacc61e39701cf9b46b"
                 "d25bf5f0595bbe24655141438e7a100b"));
    // TEST 2: the one-byte message 0x72.
    std::array<uint8_t, 32> seed2 {};
    const auto s2 = unhex("4ccd089b28ff96da9db6c346ec114e0f"
                          "5b8a319f35aba624da8cf6ed4fb8a6fb");
    std::copy(s2.begin(), s2.end(), seed2.begin());
    const uint8_t msg2[] = { 0x72 };
    const auto sig2 = izan::crypto::sol_sign(seed2, msg2);
    CHECK(std::vector<uint8_t>(sig2.begin(), sig2.end())
        == unhex("92a009a9f0d4cab8720e820b5f642540"
                 "a2b27b5416503f8fb3762223ebdb69da"
                 "085ac1e43e15996e458f3613d0f11d8c"
                 "387b2eaeb4302aeeb00d291612bb0c00"));
}

TEST_CASE("a self-transfer wears the two-key shape and reads back whole")
{
    const char* me = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    std::array<uint8_t, 32> hash {};
    hash.fill(0x22);
    const auto msg = izan::sol::encode_transfer_message(me, me, 7777, hash);
    // 3 header + 1 count + 64 keys + 32 hash + 1 + 1 + 1 + 2 + 1 + 12.
    CHECK(msg.size() == 118);
    const auto back = izan::sol::parse_transfer_message(msg);
    CHECK(back.from == me);
    CHECK(back.to == me);
    CHECK(back.lamports == 7777);

    // The whitelist holds for this shape too: wrong program index,
    // wrong account refs, foreign program bytes — all refused.
    auto tamper = [&](std::size_t at, uint8_t v) {
        auto bad = msg;
        bad[at] = v;
        return bad;
    };
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(3, 4)));
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(38, 1)));  // program
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(101, 2))); // idx
    CHECK_THROWS(izan::sol::parse_transfer_message(tamper(104, 1))); // refs
}

TEST_CASE("the ATA falls off the curve exactly where the duel says")
{
    // Anchor generated by the independent pure-python implementation
    // in tests/data/derive_vectors.py (PDA + ed25519 decompression):
    // owner HAgk14…, mint USDC → bump 254.
    CHECK(izan::crypto::sol_ata("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
              "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        == "5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt");
    // A real public key sits ON the curve; its own bytes are exactly
    // what a PDA must never be.
    std::array<uint8_t, 32> pk {};
    std::size_t sz = pk.size();
    REQUIRE(b58tobin(
        pk.data(), &sz, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"));
    CHECK(izan::crypto::sol_on_curve(pk));
    CHECK_THROWS(izan::crypto::sol_ata("junk", "junk"));
}

TEST_CASE("the SPL transfer wears one shape and the table cannot be rerouted")
{
    const char* alice = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    const char* bob = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
    const char* usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    std::array<uint8_t, 32> hash {};
    hash.fill(0x33);
    const auto msg
        = izan::sol::encode_spl_transfer(alice, bob, usdc, 2500000, 6, hash);
    const auto back = izan::sol::parse_spl_transfer(msg);
    CHECK(back.owner == alice);
    CHECK(back.dest == bob);
    CHECK(back.mint == usdc);
    CHECK(back.amount == 2500000);
    CHECK(back.decimals == 6);
    CHECK(back.blockhash == hash);

    // Zero amounts are refused up front, whatever the shape.
    CHECK_THROWS(izan::sol::encode_spl_transfer(alice, bob, usdc, 0, 6, hash));
    CHECK_THROWS(
        izan::sol::encode_spl_transfer(alice, alice, usdc, 0, 6, hash));

    // The whitelist: reroute any account and the parser walks away.
    auto tamper = [&](std::size_t at, uint8_t v) {
        auto bad = msg;
        bad[at] ^= v;
        return bad;
    };
    // keys start at offset 4; flipping a byte inside src ATA (idx 1),
    // dst ATA (idx 2) or the token program (idx 6) must all refuse.
    CHECK_THROWS(izan::sol::parse_spl_transfer(tamper(4 + 32 + 5, 0x01)));
    CHECK_THROWS(izan::sol::parse_spl_transfer(tamper(4 + 64 + 5, 0x01)));
    CHECK_THROWS(izan::sol::parse_spl_transfer(tamper(4 + 192 + 5, 0x01)));
    // The System transfer parser must not accept this shape either.
    CHECK_THROWS(izan::sol::parse_transfer_message(msg));
    auto trailing = msg;
    trailing.push_back(0);
    CHECK_THROWS(izan::sol::parse_spl_transfer(trailing));
}

TEST_CASE("a Token-2022 transfer keeps its own program and its own doors")
{
    const char* alice = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    const char* bob = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
    const char* pump = "3WjLscH2JsXLEFJZRA9z8ti8yRGxWGKbqymPd7UicRth";
    std::array<uint8_t, 32> hash {};
    hash.fill(0x44);
    const auto msg
        = izan::sol::encode_spl_transfer(alice, bob, pump, 777, 6, hash, true);
    const auto back = izan::sol::parse_spl_transfer(msg);
    CHECK(back.token2022);
    CHECK(back.mint == pump);
    CHECK(back.amount == 777);

    // The two program families never share an ATA: the same holding
    // encoded classic parses as classic yet lands elsewhere.
    const auto classic
        = izan::sol::encode_spl_transfer(alice, bob, pump, 777, 6, hash);
    CHECK(!izan::sol::parse_spl_transfer(classic).token2022);
    CHECK(izan::crypto::sol_ata(alice, pump, true)
        != izan::crypto::sol_ata(alice, pump));

    // Swapping ONLY the program key leaves the ATAs derived under the
    // other program — the duel must refuse the half-breed.
    auto half = msg;
    const auto classic_keys = std::span(classic).subspan(4 + 192, 32);
    std::copy(classic_keys.begin(), classic_keys.end(), half.begin() + 4 + 192);
    CHECK_THROWS(izan::sol::parse_spl_transfer(half));
}

TEST_CASE("an SPL self-transfer wears its own smaller table")
{
    const char* alice = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    const char* pump = "3WjLscH2JsXLEFJZRA9z8ti8yRGxWGKbqymPd7UicRth";
    std::array<uint8_t, 32> hash {};
    hash.fill(0x55);
    for (const bool t22 : { false, true }) {
        const auto msg = izan::sol::encode_spl_transfer(
            alice, alice, pump, 321, 6, hash, t22);
        const auto back = izan::sol::parse_spl_transfer(msg);
        CHECK(back.owner == alice);
        CHECK(back.dest == alice);
        CHECK(back.mint == pump);
        CHECK(back.amount == 321);
        CHECK(back.token2022 == t22);
        // Reroute the single ATA and the duel walks away.
        auto bad = msg;
        bad[4 + 32 + 7] ^= 0x01;
        CHECK_THROWS(izan::sol::parse_spl_transfer(bad));
        // The System parser refuses the shape outright.
        CHECK_THROWS(izan::sol::parse_transfer_message(msg));
        auto trailing = msg;
        trailing.push_back(0);
        CHECK_THROWS(izan::sol::parse_spl_transfer(trailing));
    }
}
