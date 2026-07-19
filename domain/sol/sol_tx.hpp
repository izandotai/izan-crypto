#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace izan::sol {

// Solana legacy transaction encoding, transfers only — the exact
// bytes keyd signs and the approval screen decodes back. Encoder and
// parser are inverses in this TU; nothing here touches the network.

// Solana's three-byte variable length ("compact-u16", ULEB128 capped
// at u16). Exposed for its own test vectors.
void put_compact_u16(std::vector<uint8_t>& out, uint16_t v);
uint16_t take_compact_u16(std::span<const uint8_t> in, std::size_t& pos);

// The System.Transfer legacy message: header 1/0/1, accounts
// [from, to, system program], the blockhash, one instruction with
// u32le(2) || u64le(lamports). Throws on a bad address, from == to,
// or zero lamports — garbage never leaves the domain layer.
std::vector<uint8_t> encode_transfer_message(std::string_view from,
    std::string_view to, uint64_t lamports,
    std::span<const uint8_t, 32> blockhash);

struct SolTransfer {
    std::string from;
    std::string to;
    uint64_t lamports = 0;
    std::array<uint8_t, 32> blockhash {};
};

// The inverse: accepts EXACTLY the shape the encoder emits and throws
// on anything else — extra instructions, foreign programs, stowaway
// accounts. The approval screen's whitelist is this strictness.
SolTransfer parse_transfer_message(std::span<const uint8_t> message);

// signature || message, ready for base64 and sendTransaction.
std::vector<uint8_t> assemble_tx(
    std::span<const uint8_t, 64> sig, std::span<const uint8_t> message);

// ---- SPL transfers: one fixed two-instruction shape ----
//
// [create-ATA-idempotent, transferChecked]: the recipient's token
// account is opened if missing and the transfer is decimal-checked by
// the token program itself. One shape means one whitelist entry; the
// parser re-derives both ATAs from (wallet, mint) and refuses a table
// that disagrees — the accounts cannot be quietly rerouted.

struct SplTransfer {
    std::string owner;   // the signer and fee payer
    std::string dest;    // the recipient WALLET (not the token account)
    std::string mint;
    uint64_t amount = 0; // base units
    uint8_t decimals = 0;
    bool token2022 = false; // which token program the message named
    std::array<uint8_t, 32> blockhash {};
};

// Throws on owner == dest (the deduplicated table would change shape;
// send to another wallet instead), or any unreadable address.
// token2022 routes the transfer through the Token-2022 program — same
// shape, different program key and ATA derivation.
std::vector<uint8_t> encode_spl_transfer(std::string_view owner,
    std::string_view dest, std::string_view mint, uint64_t amount,
    uint8_t decimals, std::span<const uint8_t, 32> blockhash,
    bool token2022 = false);

// The exact inverse, and the whitelist: EXACTLY the shape above or a
// throw — including the ATA re-derivation duel.
SplTransfer parse_spl_transfer(std::span<const uint8_t> message);

// A serialized Solana transaction is signatures || message; these
// split and stitch it. message_of throws on a shape that does not
// carry exactly one required signature — ours.
std::span<const uint8_t> message_of(std::span<const uint8_t> tx);
std::vector<uint8_t> inject_signature(
    std::span<const uint8_t> tx, std::span<const uint8_t, 64> sig);

// The fee payer of a (possibly versioned) message — the account that
// signs and pays. Base58, or a throw on anything unreadable.
std::string message_fee_payer(std::span<const uint8_t> message);

}
