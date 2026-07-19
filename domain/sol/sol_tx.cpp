#include "domain/sol/sol_tx.hpp"

#include <cstring>
#include <stdexcept>

#include "core/crypto/sol.hpp"

extern "C" {
#include <base58.h>
}

namespace izan::sol {

namespace {

    std::array<uint8_t, 32> decode_address(std::string_view text)
    {
        std::array<uint8_t, 32> out {};
        // b58tobin writes right-aligned into the buffer it is given;
        // a Solana account is exactly 32 bytes, no more, no fewer.
        std::size_t sz = out.size();
        if (!b58tobin(out.data(), &sz, std::string(text).c_str())
            || sz != out.size())
            throw std::invalid_argument(
                "sol-tx: not a solana address: " + std::string(text));
        return out;
    }

    void put_u32le(std::vector<uint8_t>& out, uint32_t v)
    {
        for (int i = 0; i < 4; ++i)
            out.push_back(uint8_t(v >> (8 * i)));
    }

    void put_u64le(std::vector<uint8_t>& out, uint64_t v)
    {
        for (int i = 0; i < 8; ++i)
            out.push_back(uint8_t(v >> (8 * i)));
    }

}

void put_compact_u16(std::vector<uint8_t>& out, uint16_t v)
{
    uint32_t rem = v;
    while (true) {
        const uint8_t byte = rem & 0x7f;
        rem >>= 7;
        if (rem == 0) {
            out.push_back(byte);
            return;
        }
        out.push_back(byte | 0x80);
    }
}

uint16_t take_compact_u16(std::span<const uint8_t> in, std::size_t& pos)
{
    uint32_t v = 0;
    for (int shift = 0; shift < 21; shift += 7) {
        if (pos >= in.size())
            throw std::runtime_error("sol-tx: compact-u16 runs off the end");
        const uint8_t byte = in[pos++];
        v |= uint32_t(byte & 0x7f) << shift;
        if (!(byte & 0x80)) {
            if (v > 0xffff)
                throw std::runtime_error("sol-tx: compact-u16 overflow");
            return uint16_t(v);
        }
    }
    throw std::runtime_error("sol-tx: compact-u16 overlong");
}

std::vector<uint8_t> encode_transfer_message(std::string_view from,
    std::string_view to, uint64_t lamports,
    std::span<const uint8_t, 32> blockhash)
{
    if (lamports == 0)
        throw std::invalid_argument("sol-tx: zero lamports");
    const auto from_pk = decode_address(from);
    const auto to_pk = decode_address(to);
    // A self-transfer is legal money (the cheapest real-coin test
    // there is), but an account may sit on the key table only once —
    // so it wears the two-key shape, the instruction naming the same
    // index twice.
    const bool self = from == to;
    std::vector<uint8_t> out;
    // Header: 1 signature required, 0 read-only signed, 1 read-only
    // unsigned (the system program).
    out.push_back(1);
    out.push_back(0);
    out.push_back(1);
    put_compact_u16(out, self ? 2 : 3);
    out.insert(out.end(), from_pk.begin(), from_pk.end());
    if (!self)
        out.insert(out.end(), to_pk.begin(), to_pk.end());
    out.insert(out.end(), 32, 0); // system program: 32 zero bytes
    out.insert(out.end(), blockhash.begin(), blockhash.end());
    put_compact_u16(out, 1);      // one instruction
    out.push_back(self ? 1 : 2);  // program index into the key table
    put_compact_u16(out, 2);      // two account references
    out.push_back(0);
    out.push_back(self ? 0 : 1);
    put_compact_u16(out, 12);     // 4 tag + 8 lamports
    put_u32le(out, 2);            // SystemInstruction::Transfer
    put_u64le(out, lamports);
    return out;
}

SolTransfer parse_transfer_message(std::span<const uint8_t> message)
{
    std::size_t pos = 0;
    auto take = [&](std::size_t n) -> const uint8_t* {
        if (pos + n > message.size())
            throw std::runtime_error("sol-tx: message truncated");
        const uint8_t* p = message.data() + pos;
        pos += n;
        return p;
    };
    const uint8_t* header = take(3);
    if (header[0] != 1 || header[1] != 0 || header[2] != 1)
        throw std::runtime_error("sol-tx: not a single-signer transfer");
    const uint16_t keys = take_compact_u16(message, pos);
    if (keys != 2 && keys != 3)
        throw std::runtime_error("sol-tx: stowaway accounts");
    const bool self = keys == 2; // the self-transfer shape
    SolTransfer out;
    const uint8_t* from_pk = take(32);
    const uint8_t* to_pk = self ? from_pk : take(32);
    const uint8_t* program = take(32);
    for (int i = 0; i < 32; ++i)
        if (program[i] != 0)
            throw std::runtime_error("sol-tx: not the system program");
    const uint8_t* hash = take(32);
    std::memcpy(out.blockhash.data(), hash, 32);
    if (take_compact_u16(message, pos) != 1)
        throw std::runtime_error("sol-tx: expected exactly one instruction");
    if (*take(1) != (self ? 1 : 2))
        throw std::runtime_error("sol-tx: instruction on a foreign program");
    if (take_compact_u16(message, pos) != 2)
        throw std::runtime_error("sol-tx: wrong account count");
    const uint8_t* accts = take(2);
    if (accts[0] != 0 || accts[1] != (self ? 0 : 1))
        throw std::runtime_error("sol-tx: wrong account order");
    if (take_compact_u16(message, pos) != 12)
        throw std::runtime_error("sol-tx: wrong data length");
    const uint8_t* data = take(12);
    uint32_t tag = 0;
    for (int i = 0; i < 4; ++i)
        tag |= uint32_t(data[i]) << (8 * i);
    if (tag != 2)
        throw std::runtime_error("sol-tx: not a transfer instruction");
    for (int i = 0; i < 8; ++i)
        out.lamports |= uint64_t(data[4 + i]) << (8 * i);
    if (out.lamports == 0)
        throw std::runtime_error("sol-tx: zero lamports");
    if (pos != message.size())
        throw std::runtime_error("sol-tx: trailing bytes");
    out.from = crypto::sol_address(std::span<const uint8_t, 32>(from_pk, 32));
    out.to = crypto::sol_address(std::span<const uint8_t, 32>(to_pk, 32));
    return out;
}

std::vector<uint8_t> assemble_tx(
    std::span<const uint8_t, 64> sig, std::span<const uint8_t> message)
{
    std::vector<uint8_t> out;
    put_compact_u16(out, 1);
    out.insert(out.end(), sig.begin(), sig.end());
    out.insert(out.end(), message.begin(), message.end());
    return out;
}

}

namespace izan::sol {

namespace {

    const std::array<uint8_t, 32>& token_program()
    {
        static const std::array<uint8_t, 32> pk = [] {
            std::array<uint8_t, 32> out {};
            std::size_t sz = out.size();
            b58tobin(
                out.data(), &sz, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
            return out;
        }();
        return pk;
    }

    const std::array<uint8_t, 32>& token2022_program()
    {
        static const std::array<uint8_t, 32> pk = [] {
            std::array<uint8_t, 32> out {};
            std::size_t sz = out.size();
            b58tobin(
                out.data(), &sz, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
            return out;
        }();
        return pk;
    }

    const std::array<uint8_t, 32>& ata_program()
    {
        static const std::array<uint8_t, 32> pk = [] {
            std::array<uint8_t, 32> out {};
            std::size_t sz = out.size();
            b58tobin(out.data(), &sz,
                "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
            return out;
        }();
        return pk;
    }

}

namespace {

    // The self-transfer wears its own, smaller table: the wallet is
    // both payer and recipient, the single ATA appears once, and the
    // token program's own self-transfer short-circuit does the rest.
    std::vector<uint8_t> encode_spl_self(std::string_view owner,
        std::string_view mint, uint64_t amount, uint8_t decimals,
        std::span<const uint8_t, 32> blockhash, bool token2022)
    {
        const auto owner_pk = decode_address(owner);
        const auto mint_pk = decode_address(mint);
        const auto ata
            = decode_address(crypto::sol_ata(owner, mint, token2022));

        std::vector<uint8_t> out;
        out.push_back(1); // the owner signs and pays
        out.push_back(0);
        out.push_back(4); // mint, system, token, ata programs
        put_compact_u16(out, 6);
        auto put_key = [&](const std::array<uint8_t, 32>& k) {
            out.insert(out.end(), k.begin(), k.end());
        };
        put_key(owner_pk);            // 0 w signer
        put_key(ata);                 // 1 w
        put_key(mint_pk);             // 2 r
        out.insert(out.end(), 32, 0); // 3 r system program
        put_key(token2022 ? token2022_program() : token_program()); // 4 r
        put_key(ata_program());                                     // 5 r
        out.insert(out.end(), blockhash.begin(), blockhash.end());
        put_compact_u16(out, 2);
        // create-ATA, idempotent — a no-op when the door is open.
        out.push_back(5);
        put_compact_u16(out, 6);
        out.push_back(0);
        out.push_back(1);
        out.push_back(0);
        out.push_back(2);
        out.push_back(3);
        out.push_back(4);
        put_compact_u16(out, 1);
        out.push_back(1); // CreateIdempotent
        // transferChecked src == dst: validated on-chain, moves nothing,
        // costs only the fee — the cheapest honest test of a send lane.
        out.push_back(4);
        put_compact_u16(out, 4);
        out.push_back(1);
        out.push_back(2);
        out.push_back(1);
        out.push_back(0);
        put_compact_u16(out, 10);
        out.push_back(12); // TransferChecked
        for (int i = 0; i < 8; ++i)
            out.push_back(uint8_t(amount >> (8 * i)));
        out.push_back(decimals);
        return out;
    }

    SplTransfer parse_spl_self(std::span<const uint8_t> message);

}

std::vector<uint8_t> encode_spl_transfer(std::string_view owner,
    std::string_view dest, std::string_view mint, uint64_t amount,
    uint8_t decimals, std::span<const uint8_t, 32> blockhash, bool token2022)
{
    if (amount == 0)
        throw std::invalid_argument("sol-tx: zero amount");
    if (owner == dest)
        return encode_spl_self(
            owner, mint, amount, decimals, blockhash, token2022);
    const auto owner_pk = decode_address(owner);
    const auto dest_pk = decode_address(dest);
    const auto mint_pk = decode_address(mint);
    const auto src_ata
        = decode_address(crypto::sol_ata(owner, mint, token2022));
    const auto dst_ata = decode_address(crypto::sol_ata(dest, mint, token2022));

    std::vector<uint8_t> out;
    out.push_back(1); // one signature: the owner pays and signs
    out.push_back(0);
    out.push_back(5); // dest wallet, mint, system, token, ata programs
    put_compact_u16(out, 8);
    auto put_key = [&](const std::array<uint8_t, 32>& k) {
        out.insert(out.end(), k.begin(), k.end());
    };
    put_key(owner_pk);            // 0 w signer
    put_key(src_ata);             // 1 w
    put_key(dst_ata);             // 2 w
    put_key(dest_pk);             // 3 r
    put_key(mint_pk);             // 4 r
    out.insert(out.end(), 32, 0); // 5 r system program
    put_key(token2022 ? token2022_program() : token_program()); // 6 r
    put_key(ata_program());                                     // 7 r
    out.insert(out.end(), blockhash.begin(), blockhash.end());
    put_compact_u16(out, 2);
    // create-ATA, idempotent: opens the recipient's account when
    // missing, is a cheap no-op when it exists.
    out.push_back(7);
    put_compact_u16(out, 6);
    out.push_back(0);
    out.push_back(2);
    out.push_back(3);
    out.push_back(4);
    out.push_back(5);
    out.push_back(6);
    put_compact_u16(out, 1);
    out.push_back(1); // CreateIdempotent
    // transferChecked: amount and decimals both verified on-chain.
    out.push_back(6);
    put_compact_u16(out, 4);
    out.push_back(1);
    out.push_back(4);
    out.push_back(2);
    out.push_back(0);
    put_compact_u16(out, 10);
    out.push_back(12); // TransferChecked
    for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(amount >> (8 * i)));
    out.push_back(decimals);
    return out;
}

namespace {

    // The self shape's exact inverse — the whitelist's second admissible
    // SPL grammar, no laxer than the first.
    SplTransfer parse_spl_self(std::span<const uint8_t> message)
    {
        std::size_t pos = 0;
        auto take = [&](std::size_t n) -> const uint8_t* {
            if (pos + n > message.size())
                throw std::runtime_error("sol-tx: message truncated");
            const uint8_t* p = message.data() + pos;
            pos += n;
            return p;
        };
        const uint8_t* header = take(3);
        if (header[0] != 1 || header[1] != 0 || header[2] != 4)
            throw std::runtime_error("sol-tx: not the spl-self shape");
        if (take_compact_u16(message, pos) != 6)
            throw std::runtime_error("sol-tx: wrong account count");
        std::array<std::array<uint8_t, 32>, 6> keys;
        for (auto& k : keys)
            std::memcpy(k.data(), take(32), 32);
        for (int i = 0; i < 32; ++i)
            if (keys[3][std::size_t(i)] != 0)
                throw std::runtime_error("sol-tx: not the system program slot");
        if (keys[5] != ata_program())
            throw std::runtime_error("sol-tx: foreign program in the table");

        SplTransfer out;
        if (keys[4] == token2022_program())
            out.token2022 = true;
        else if (keys[4] != token_program())
            throw std::runtime_error("sol-tx: foreign program in the table");
        std::memcpy(out.blockhash.data(), take(32), 32);
        if (take_compact_u16(message, pos) != 2)
            throw std::runtime_error(
                "sol-tx: expected exactly two instructions");
        static constexpr uint8_t kCreateRefs[6] = { 0, 1, 0, 2, 3, 4 };
        if (*take(1) != 5 || take_compact_u16(message, pos) != 6)
            throw std::runtime_error("sol-tx: first instruction misshapen");
        if (std::memcmp(take(6), kCreateRefs, 6) != 0)
            throw std::runtime_error("sol-tx: first instruction misshapen");
        if (take_compact_u16(message, pos) != 1 || *take(1) != 1)
            throw std::runtime_error("sol-tx: first instruction misshapen");
        static constexpr uint8_t kXferRefs[4] = { 1, 2, 1, 0 };
        if (*take(1) != 4 || take_compact_u16(message, pos) != 4)
            throw std::runtime_error("sol-tx: second instruction misshapen");
        if (std::memcmp(take(4), kXferRefs, 4) != 0)
            throw std::runtime_error("sol-tx: second instruction misshapen");
        if (take_compact_u16(message, pos) != 10)
            throw std::runtime_error("sol-tx: wrong data length");
        const uint8_t* data = take(10);
        if (data[0] != 12)
            throw std::runtime_error("sol-tx: not a transferChecked");
        for (int i = 0; i < 8; ++i)
            out.amount |= uint64_t(data[1 + i]) << (8 * i);
        if (out.amount == 0)
            throw std::runtime_error("sol-tx: zero amount");
        out.decimals = data[9];
        if (pos != message.size())
            throw std::runtime_error("sol-tx: trailing bytes");

        out.owner = crypto::sol_address(keys[0]);
        out.dest = out.owner;
        out.mint = crypto::sol_address(keys[2]);
        // The ATA duel, single door: the one token account must be
        // exactly the owner's canonical one.
        if (decode_address(crypto::sol_ata(out.owner, out.mint, out.token2022))
            != keys[1])
            throw std::runtime_error("sol-tx: token accounts off the canon");
        return out;
    }

}

SplTransfer parse_spl_transfer(std::span<const uint8_t> message)
{
    std::size_t pos = 0;
    auto take = [&](std::size_t n) -> const uint8_t* {
        if (pos + n > message.size())
            throw std::runtime_error("sol-tx: message truncated");
        const uint8_t* p = message.data() + pos;
        pos += n;
        return p;
    };
    const uint8_t* header = take(3);
    if (header[0] == 1 && header[1] == 0 && header[2] == 4)
        return parse_spl_self(message);
    if (header[0] != 1 || header[1] != 0 || header[2] != 5)
        throw std::runtime_error("sol-tx: not the spl-transfer shape");
    if (take_compact_u16(message, pos) != 8)
        throw std::runtime_error("sol-tx: wrong account count");
    std::array<std::array<uint8_t, 32>, 8> keys;
    for (auto& k : keys)
        std::memcpy(k.data(), take(32), 32);
    for (int i = 0; i < 32; ++i)
        if (keys[5][std::size_t(i)] != 0)
            throw std::runtime_error("sol-tx: not the system program slot");
    if (keys[7] != ata_program())
        throw std::runtime_error("sol-tx: foreign program in the table");

    SplTransfer out;
    if (keys[6] == token2022_program())
        out.token2022 = true;
    else if (keys[6] != token_program())
        throw std::runtime_error("sol-tx: foreign program in the table");
    std::memcpy(out.blockhash.data(), take(32), 32);
    if (take_compact_u16(message, pos) != 2)
        throw std::runtime_error("sol-tx: expected exactly two instructions");
    // Instruction one: the idempotent ATA create, byte for byte.
    static constexpr uint8_t kCreateRefs[6] = { 0, 2, 3, 4, 5, 6 };
    if (*take(1) != 7 || take_compact_u16(message, pos) != 6)
        throw std::runtime_error("sol-tx: first instruction misshapen");
    const uint8_t* refs1 = take(6);
    if (std::memcmp(refs1, kCreateRefs, 6) != 0)
        throw std::runtime_error("sol-tx: first instruction misshapen");
    if (take_compact_u16(message, pos) != 1 || *take(1) != 1)
        throw std::runtime_error("sol-tx: first instruction misshapen");
    // Instruction two: transferChecked.
    static constexpr uint8_t kXferRefs[4] = { 1, 4, 2, 0 };
    if (*take(1) != 6 || take_compact_u16(message, pos) != 4)
        throw std::runtime_error("sol-tx: second instruction misshapen");
    const uint8_t* refs2 = take(4);
    if (std::memcmp(refs2, kXferRefs, 4) != 0)
        throw std::runtime_error("sol-tx: second instruction misshapen");
    if (take_compact_u16(message, pos) != 10)
        throw std::runtime_error("sol-tx: wrong data length");
    const uint8_t* data = take(10);
    if (data[0] != 12)
        throw std::runtime_error("sol-tx: not a transferChecked");
    for (int i = 0; i < 8; ++i)
        out.amount |= uint64_t(data[1 + i]) << (8 * i);
    if (out.amount == 0)
        throw std::runtime_error("sol-tx: zero amount");
    out.decimals = data[9];
    if (pos != message.size())
        throw std::runtime_error("sol-tx: trailing bytes");

    out.owner = crypto::sol_address(keys[0]);
    out.dest = crypto::sol_address(keys[3]);
    out.mint = crypto::sol_address(keys[4]);
    // The ATA duel: the table's token accounts must be exactly the
    // canonical ones for (wallet, mint) under the token program the
    // message itself named — nowhere else money could be quietly
    // pointed.
    if (decode_address(crypto::sol_ata(out.owner, out.mint, out.token2022))
            != keys[1]
        || decode_address(crypto::sol_ata(out.dest, out.mint, out.token2022))
            != keys[2])
        throw std::runtime_error("sol-tx: token accounts off the canon");
    return out;
}

std::span<const uint8_t> message_of(std::span<const uint8_t> tx)
{
    std::size_t pos = 0;
    const uint16_t nsigs = take_compact_u16(tx, pos);
    if (nsigs != 1)
        throw std::runtime_error("sol-tx: expected exactly one signature slot");
    if (tx.size() <= pos + 64)
        throw std::runtime_error("sol-tx: transaction truncated");
    return tx.subspan(pos + 64);
}

std::vector<uint8_t> inject_signature(
    std::span<const uint8_t> tx, std::span<const uint8_t, 64> sig)
{
    const std::span<const uint8_t> msg = message_of(tx); // validates shape
    std::vector<uint8_t> out;
    out.reserve(1 + 64 + msg.size());
    out.push_back(1);
    out.insert(out.end(), sig.begin(), sig.end());
    out.insert(out.end(), msg.begin(), msg.end());
    return out;
}

std::string message_fee_payer(std::span<const uint8_t> message)
{
    std::size_t pos = 0;
    if (message.empty())
        throw std::runtime_error("sol-tx: empty message");
    // Versioned messages carry a version byte with the high bit set;
    // legacy messages start straight at the header.
    if (message[0] & 0x80) {
        if ((message[0] & 0x7f) != 0)
            throw std::runtime_error("sol-tx: unknown message version");
        pos = 1;
    }
    if (message.size() < pos + 3)
        throw std::runtime_error("sol-tx: message truncated");
    const uint8_t required = message[pos];
    if (required != 1)
        throw std::runtime_error("sol-tx: expected a single signer");
    pos += 3;
    const uint16_t keys = take_compact_u16(message, pos);
    if (keys == 0 || message.size() < pos + 32)
        throw std::runtime_error("sol-tx: message truncated");
    std::array<uint8_t, 32> payer {};
    std::memcpy(payer.data(), message.data() + pos, 32);
    return crypto::sol_address(payer);
}

}
