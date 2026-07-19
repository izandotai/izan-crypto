// The EIP-712 machinery against the specification's own "Ether Mail"
// example — domain separator, nested struct hashing and the final
// signing digest, all three pinned to the values in the EIP.

#include <doctest/doctest.h>

#include <string>

#include "core/crypto/eip712.hpp"

namespace {

using izan::crypto::eip712::EthAddress;
using izan::crypto::eip712::Hash32;

EthAddress addr(const char* hex40)
{
    auto nib = [](char c) {
        return uint8_t(c <= '9' ? c - '0' : (c & 0x5f) - 'A' + 10);
    };
    EthAddress out {};
    for (int i = 0; i < 20; ++i)
        out[std::size_t(i)]
            = uint8_t(nib(hex40[2 * i]) << 4 | nib(hex40[2 * i + 1]));
    return out;
}

std::string hex_of(const Hash32& h)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : h) {
        out += digits[b >> 4];
        out += digits[b & 0xf];
    }
    return out;
}

}

TEST_CASE("the Ether Mail example signs exactly as the EIP says")
{
    namespace e = izan::crypto::eip712;

    const Hash32 domain = e::domain_separator(
        "Ether Mail", "1", 1, addr("CcCcccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"));
    CHECK(hex_of(domain)
        == "f2cee375fa42b42143804025fc449deaf"
           "d50cc031ca257e0b194a650a912090f");

    const Hash32 person_type
        = e::keccak256(std::string_view("Person(string name,address wallet)"));
    auto person = [&](const char* name, const char* wallet) {
        std::vector<uint8_t> buf;
        e::append_word(buf, person_type);
        e::append_word(buf, e::keccak256(std::string_view(name)));
        e::append_address(buf, addr(wallet));
        return e::keccak256(buf);
    };
    const Hash32 mail_type = e::keccak256(std::string_view(
        "Mail(Person from,Person to,string contents)Person(string "
        "name,address wallet)"));
    std::vector<uint8_t> mail;
    e::append_word(mail, mail_type);
    e::append_word(
        mail, person("Cow", "CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"));
    e::append_word(
        mail, person("Bob", "bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"));
    e::append_word(mail, e::keccak256(std::string_view("Hello, Bob!")));
    const Hash32 struct_hash = e::keccak256(mail);
    CHECK(hex_of(struct_hash)
        == "c52c0ee5d84264471806290a3f2c4cecf"
           "c5490626bf912d01f240d7a274b371e");

    CHECK(hex_of(e::typed_digest(domain, struct_hash))
        == "be609aee343fb3c4b28e1df9e632fca64"
           "fcfaede20f02e86244efddf30957bd2");
}
