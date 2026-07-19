# izan-crypto

Multi-chain wallet cryptography for C++23, fully static, zero network.

- **HD derivation**: BIP-39/32, SLIP-0010 (ed25519, hardened-only)
- **Addresses**: EVM (EIP-55), Bitcoin (P2PKH / P2SH-P2WPKH / P2WPKH /
  P2TR / P2WSH / P2SH-P2WSH), Solana (base58, ATA/PDA derivation)
- **Signatures**: secp256k1 (RFC 6979 low-s), BIP-340 schnorr with
  BIP-341 key tweaking, ed25519 (RFC 8032)
- **Transaction grammar**: EIP-1559, Bitcoin segwit/legacy/taproot
  (BIP-143 / BIP-341 sighashes), Solana legacy messages and SPL
  transfers — encoders and strict parsers as inverses, built for
  signing planes that must display exactly what they sign
- **Money arithmetic**: exact U256 with checked decimal conversion
- **Key hygiene**: guarded, wiped allocations (libsodium) end to end

Every primitive is pinned to its official test vectors (BIP-39/32/84/
86, SLIP-0010, EIP-55, BIP-143, BIP-340, RFC 8032) plus independent
dual-implementation duels; see `tests/`.

Dependencies (trezor-crypto, libsodium, doctest) are fetched as pinned
release tarballs and built from source. No system packages, no dynamic
libraries beyond the OS.

```cmake
include(FetchContent)
FetchContent_Declare(izan_crypto
    GIT_REPOSITORY https://github.com/izandotai/izan-crypto.git
    GIT_TAG v0.1.0)
FetchContent_MakeAvailable(izan_crypto)
target_link_libraries(app PRIVATE izan::crypto izan::soltx izan::btctx)
```

## License

MIT. Used by the [Izan wallet](https://github.com/izandotai/wallet)
(GPL-3.0) and related tooling.
