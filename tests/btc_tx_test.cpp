// The Bitcoin transaction grammar against its own vectors — moved
// home from the wallet's suite: the BIP-143 sighash pinned to the
// spec's Native P2WPKH example, the skeleton round trip, and the
// address↔script inverses across every costume.

#include <doctest/doctest.h>

#include <array>
#include <span>
#include <string>
#include <vector>

#include "domain/btc/btc_tx.hpp"

namespace {

std::vector<uint8_t> unhex_btc(const char* h)
{
    std::vector<uint8_t> out;
    for (const char* p = h; p[0] && p[1]; p += 2) {
        auto nib
            = [](char c) { return uint8_t(c <= '9' ? c - '0' : c - 'a' + 10); };
        out.push_back(uint8_t(nib(p[0]) << 4 | nib(p[1])));
    }
    return out;
}

std::array<uint8_t, 32> txid_be_of_wire(const char* wire_le_hex)
{
    const auto le = unhex_btc(wire_le_hex);
    std::array<uint8_t, 32> be {};
    for (int i = 0; i < 32; ++i)
        be[std::size_t(i)] = le[std::size_t(31 - i)];
    return be;
}

}

TEST_CASE("BIP-143 signs exactly what the spec says it signs")
{
    // The Native P2WPKH example from the BIP itself, verbatim.
    izan::btc::TxPlan plan;
    plan.version = 1;
    plan.locktime = 17;
    izan::btc::TxPlan::In in0;
    in0.txid_be = txid_be_of_wire("fff7f7881a8099afa6940d42d1e7f636"
                                  "2bec38171ea3edf433541db4e4ad969f");
    in0.vout = 0;
    in0.sequence = 0xffffffee;
    izan::btc::TxPlan::In in1;
    in1.txid_be = txid_be_of_wire("ef51e1b804cc89d182d279655c3aa89e"
                                  "815b1b309fe287d9b2b55d57b90ec68a");
    in1.vout = 1;
    in1.value = 600000000;
    in1.sequence = 0xffffffff;
    plan.inputs = { in0, in1 };
    izan::btc::TxPlan::Out out0;
    out0.value = 112340000;
    out0.script
        = unhex_btc("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac");
    izan::btc::TxPlan::Out out1;
    out1.value = 223450000;
    out1.script
        = unhex_btc("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac");
    plan.outputs = { out0, out1 };

    const auto h160 = unhex_btc("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1");
    const auto digest = izan::btc::sighash_p2wpkh(
        plan, 1, std::span<const uint8_t, 20>(h160.data(), 20));
    CHECK(std::vector<uint8_t>(digest.begin(), digest.end())
        == unhex_btc("c37af31116d1b27caf68aae9e3ac82f1"
                     "477929014d5b917657d0eb49478cb670"));

    // The skeleton round-trips (values do not ride the wire).
    const auto skel = izan::btc::encode_skeleton(plan);
    const auto back = izan::btc::parse_skeleton(skel);
    CHECK(back.inputs.size() == 2);
    CHECK(back.inputs[1].vout == 1);
    CHECK(back.inputs[0].sequence == 0xffffffee);
    CHECK(back.outputs[1].value == 223450000);
    CHECK(back.locktime == 17);
    CHECK(izan::btc::encode_skeleton(back) == skel);
    auto broken = skel;
    broken.pop_back();
    CHECK_THROWS(izan::btc::parse_skeleton(broken));
}

TEST_CASE("addresses and scripts are inverses across every costume")
{
    const char* faces[] = {
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "3NVZWnhKt53ukKw4Qm217Zk57FE8VnKjH2",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    };
    for (const char* face : faces) {
        const auto script = izan::btc::script_for_address(face);
        CHECK(izan::btc::address_for_script(script) == face);
    }
    CHECK_THROWS(izan::btc::script_for_address("not-an-address"));
    const uint8_t junk[] = { 0x6a, 0x02, 0xaa, 0xbb }; // OP_RETURN
    CHECK(izan::btc::address_for_script(junk).empty());
}
