#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>

#include "core/secure/secure_bytes.hpp"

namespace izan::crypto {

// Recoverable secp256k1 signature over a 32-byte digest: deterministic
// nonce (RFC 6979), canonical low s. y_parity is the Ethereum recovery bit.
struct EcdsaSignature {
    std::array<uint8_t, 32> r {};
    std::array<uint8_t, 32> s {};
    uint8_t y_parity = 0;
};

// A validated raw secp256k1 scalar held in libsodium guarded memory.
// Secret acquisition stays with the application: this boundary receives
// exactly 32 bytes, protects the pages while idle, and wipes on destruction.
class Secp256k1PrivateKey {
public:
    static std::optional<Secp256k1PrivateKey> from_bytes(
        std::span<const uint8_t, 32> bytes);

    std::array<uint8_t, 65> public_key_uncompressed() const;
    std::array<uint8_t, 33> public_key_compressed() const;
    std::optional<EcdsaSignature> sign_digest(
        std::span<const uint8_t, 32> digest) const;

    Secp256k1PrivateKey(const Secp256k1PrivateKey&) = delete;
    Secp256k1PrivateKey& operator=(const Secp256k1PrivateKey&) = delete;
    Secp256k1PrivateKey(Secp256k1PrivateKey&&) noexcept = default;
    Secp256k1PrivateKey& operator=(Secp256k1PrivateKey&&) noexcept = default;

private:
    explicit Secp256k1PrivateKey(secure::SecureBytes bytes);
    mutable secure::SecureBytes bytes_;
};

}
