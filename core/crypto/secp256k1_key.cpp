#include "core/crypto/secp256k1_key.hpp"

#include <algorithm>
#include <utility>

extern "C" {
#include <ecdsa.h>
#include <memzero.h>
#include <secp256k1.h>
}

namespace izan::crypto {

Secp256k1PrivateKey::Secp256k1PrivateKey(secure::SecureBytes bytes)
    : bytes_(std::move(bytes))
{
    bytes_.protect();
}

std::optional<Secp256k1PrivateKey> Secp256k1PrivateKey::from_bytes(
    std::span<const uint8_t, 32> bytes)
{
    secure::SecureBytes guarded(32);
    std::copy(bytes.begin(), bytes.end(), guarded.data());
    std::array<uint8_t, 65> public_key {};
    if (ecdsa_get_public_key65(&secp256k1, guarded.data(), public_key.data())
        != 0) {
        memzero(public_key.data(), public_key.size());
        return std::nullopt;
    }
    memzero(public_key.data(), public_key.size());
    return Secp256k1PrivateKey { std::move(guarded) };
}

std::array<uint8_t, 65> Secp256k1PrivateKey::public_key_uncompressed() const
{
    secure::SecureBytes::Access access(bytes_);
    std::array<uint8_t, 65> out {};
    if (ecdsa_get_public_key65(&secp256k1, bytes_.data(), out.data()) != 0)
        out.fill(0);
    return out;
}

std::array<uint8_t, 33> Secp256k1PrivateKey::public_key_compressed() const
{
    secure::SecureBytes::Access access(bytes_);
    std::array<uint8_t, 33> out {};
    if (ecdsa_get_public_key33(&secp256k1, bytes_.data(), out.data()) != 0)
        out.fill(0);
    return out;
}

std::optional<EcdsaSignature> Secp256k1PrivateKey::sign_digest(
    std::span<const uint8_t, 32> digest) const
{
    secure::SecureBytes::Access access(bytes_);
    uint8_t signature[64] {};
    uint8_t parity = 0;
    if (ecdsa_sign_digest(&secp256k1, bytes_.data(), digest.data(), signature,
            &parity, nullptr)
        != 0) {
        memzero(signature, sizeof signature);
        return std::nullopt;
    }
    EcdsaSignature out;
    std::copy(signature, signature + 32, out.r.begin());
    std::copy(signature + 32, signature + 64, out.s.begin());
    out.y_parity = parity;
    memzero(signature, sizeof signature);
    return out;
}

}
