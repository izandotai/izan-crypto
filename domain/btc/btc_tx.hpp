#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace izan::btc {

// The transaction the wallet plans and keyd reads back: P2WPKH inputs
// only (v1), any standard single-key output. Everything here is pure
// bytes — no network, shared by the send flow and the trust plane.

// RBF by default: replaceable, still locktime-honest.
inline constexpr uint32_t kSequenceRbf = 0xfffffffd;

// What script the spent coins live under. One kind per plan — a
// wallet spends from its own format, and every input wears it.
enum class SpendKind : uint8_t {
    P2wpkh,     // bc1q — BIP-143, witness sig+pubkey
    P2pkh,      // 1…   — legacy sighash, scriptSig sig+pubkey
    P2shP2wpkh, // 3…   — BIP-143, plus the one-push redeem scriptSig
    P2tr,       // bc1p — BIP-341 key path, single schnorr witness
};

struct TxPlan {
    struct In {
        std::array<uint8_t, 32> txid_be {}; // as explorers print it
        uint32_t vout = 0;
        uint64_t value = 0; // satoshi — BIP-143 signs the amount
        uint32_t sequence = kSequenceRbf;
    };

    struct Out {
        std::vector<uint8_t> script;
        uint64_t value = 0;
    };

    std::vector<In> inputs;
    std::vector<Out> outputs;
    uint32_t version = 2;
    uint32_t locktime = 0;
    // Local metadata, never serialized: the skeleton on the wire is
    // format-blind, and the signer re-derives the kind from the
    // envelope preset it trusts.
    SpendKind spend = SpendKind::P2wpkh;
};

// Address ↔ scriptPubKey, both directions. Encode throws on an
// unknown address form; decode returns empty for a script no address
// can name (the whitelist treats that as refusal).
std::vector<uint8_t> script_for_address(std::string_view address);
std::string address_for_script(std::span<const uint8_t> script);

// The unsigned skeleton: what rides the proposal queue and what the
// txid is computed over (witnesses never touch the txid).
std::vector<uint8_t> encode_skeleton(const TxPlan& plan);
TxPlan parse_skeleton(std::span<const uint8_t> bytes); // throws on junk
// Skeleton values are not serialized (BIP-143 needs them; they ride
// the envelope separately) — parse_skeleton leaves them zero.

// BIP-143 digest for one P2WPKH input: what the key actually signs.
// pubkey_hash160 is the spent output's own program. Nested segwit
// signs the very same digest — only the wrapper differs.
std::array<uint8_t, 32> sighash_p2wpkh(const TxPlan& plan,
    std::size_t input_index, std::span<const uint8_t, 20> pubkey_hash160);

// The pre-segwit digest for one P2PKH input: the whole transaction
// with the spent output's script standing in the signed slot.
std::array<uint8_t, 32> sighash_p2pkh(const TxPlan& plan,
    std::size_t input_index, std::span<const uint8_t, 20> pubkey_hash160);

// BIP-341 key-path digest (SIGHASH_DEFAULT). Taproot commits to every
// input's amount and scriptPubKey; own_script is the account's own
// P2TR output script, worn by all inputs of the plan.
std::array<uint8_t, 32> sighash_p2tr(const TxPlan& plan,
    std::size_t input_index, std::span<const uint8_t> own_script);

// The final wire bytes, one witness per input in order. For the ECDSA
// kinds signature_der is the DER signature without the hashtype byte
// and pubkey rides along; for taproot signature_der is the bare
// 64-byte schnorr signature and pubkey is unused.
struct Witness {
    std::vector<uint8_t> signature_der;
    std::array<uint8_t, 33> pubkey {};
};

std::vector<uint8_t> assemble_tx(
    const TxPlan& plan, std::span<const Witness> witnesses);

// txid (big-endian hex, as explorers print it). The witness kinds
// know it from the skeleton alone; a legacy spend's txid covers its
// scriptSigs, so it needs the witnesses.
std::string txid_of(const TxPlan& plan);
std::string txid_of_signed(
    const TxPlan& plan, std::span<const Witness> witnesses);
uint64_t vsize_of(const TxPlan& plan, std::span<const Witness> witnesses);

}
