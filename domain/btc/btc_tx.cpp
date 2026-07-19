#include "domain/btc/btc_tx.hpp"

#include <cstring>
#include <stdexcept>

extern "C" {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvolatile"
#include <base58.h>
#include <hasher.h>
#include <ripemd160.h>
#include <segwit_addr.h>
#include <sha2.h>
#pragma GCC diagnostic pop
}

namespace izan::btc {

namespace {

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

    // The compact size: one byte to 252, then tagged widths.
    void put_varint(std::vector<uint8_t>& out, uint64_t v)
    {
        if (v < 0xfd) {
            out.push_back(uint8_t(v));
        } else if (v <= 0xffff) {
            out.push_back(0xfd);
            out.push_back(uint8_t(v));
            out.push_back(uint8_t(v >> 8));
        } else {
            out.push_back(0xfe);
            put_u32le(out, uint32_t(v));
        }
    }

    struct Reader {
        std::span<const uint8_t> in;
        std::size_t pos = 0;

        const uint8_t* take(std::size_t n)
        {
            if (pos + n > in.size())
                throw std::runtime_error("btc-tx: truncated");
            const uint8_t* p = in.data() + pos;
            pos += n;
            return p;
        }

        uint32_t u32()
        {
            const uint8_t* p = take(4);
            return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16
                | uint32_t(p[3]) << 24;
        }

        uint64_t u64()
        {
            uint64_t v = 0;
            const uint8_t* p = take(8);
            for (int i = 0; i < 8; ++i)
                v |= uint64_t(p[i]) << (8 * i);
            return v;
        }

        uint64_t varint()
        {
            const uint8_t tag = *take(1);
            if (tag < 0xfd)
                return tag;
            if (tag == 0xfd) {
                const uint8_t* p = take(2);
                return uint64_t(p[0]) | uint64_t(p[1]) << 8;
            }
            if (tag == 0xfe)
                return u32();
            throw std::runtime_error("btc-tx: 8-byte counts are not money");
        }
    };

    std::array<uint8_t, 32> sha256d(std::span<const uint8_t> bytes)
    {
        std::array<uint8_t, 32> out;
        sha256_Raw(bytes.data(), bytes.size(), out.data());
        sha256_Raw(out.data(), out.size(), out.data());
        return out;
    }

    void put_outpoint(std::vector<uint8_t>& out, const TxPlan::In& in)
    {
        // The wire wants the txid little-endian — reversed from print.
        for (int i = 31; i >= 0; --i)
            out.push_back(in.txid_be[std::size_t(i)]);
        put_u32le(out, in.vout);
    }

    void put_outputs(std::vector<uint8_t>& out, const TxPlan& plan)
    {
        put_varint(out, plan.outputs.size());
        for (const TxPlan::Out& o : plan.outputs) {
            put_u64le(out, o.value);
            put_varint(out, o.script.size());
            out.insert(out.end(), o.script.begin(), o.script.end());
        }
    }

}

std::vector<uint8_t> script_for_address(std::string_view address)
{
    const std::string z(address);
    std::vector<uint8_t> script;
    if (address.starts_with("bc1") || address.starts_with("BC1")) {
        int version = 0;
        uint8_t program[40];
        size_t program_len = 0;
        if (segwit_addr_decode(&version, program, &program_len, "bc", z.c_str())
                != 1
            || (version == 0 && program_len != 20 && program_len != 32)
            || (version == 1 && program_len != 32))
            throw std::invalid_argument("btc-tx: unreadable bech32 address");
        script.push_back(version == 0 ? 0x00 : uint8_t(0x50 + version));
        script.push_back(uint8_t(program_len));
        script.insert(script.end(), program, program + program_len);
        return script;
    }
    uint8_t payload[21];
    if (base58_decode_check(z.c_str(), HASHER_SHA2D, payload, sizeof payload)
        != sizeof payload)
        throw std::invalid_argument("btc-tx: unreadable base58 address");
    if (payload[0] == 0x00) {
        // P2PKH: DUP HASH160 push20 <h160> EQUALVERIFY CHECKSIG
        script = { 0x76, 0xa9, 0x14 };
        script.insert(script.end(), payload + 1, payload + 21);
        script.push_back(0x88);
        script.push_back(0xac);
        return script;
    }
    if (payload[0] == 0x05) {
        // P2SH: HASH160 push20 <h160> EQUAL
        script = { 0xa9, 0x14 };
        script.insert(script.end(), payload + 1, payload + 21);
        script.push_back(0x87);
        return script;
    }
    throw std::invalid_argument("btc-tx: unknown address version");
}

std::string address_for_script(std::span<const uint8_t> script)
{
    char addr[93];
    if (script.size() >= 2 && (script[0] == 0x00 || script[0] == 0x51)
        && script[1] == script.size() - 2) {
        const int version = script[0] == 0x00 ? 0 : 1;
        if (segwit_addr_encode(
                addr, "bc", version, script.data() + 2, script.size() - 2)
            == 1)
            return addr;
        return {};
    }
    auto b58 = [&](uint8_t ver, const uint8_t* h160) -> std::string {
        uint8_t payload[21];
        payload[0] = ver;
        std::memcpy(payload + 1, h160, 20);
        char a[40];
        if (base58_encode_check(payload, 21, HASHER_SHA2D, a, sizeof a) <= 0)
            return {};
        return a;
    };
    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9
        && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
        return b58(0x00, script.data() + 3);
    if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14
        && script[22] == 0x87)
        return b58(0x05, script.data() + 2);
    return {};
}

std::vector<uint8_t> encode_skeleton(const TxPlan& plan)
{
    if (plan.inputs.empty() || plan.outputs.empty())
        throw std::invalid_argument("btc-tx: an empty side");
    std::vector<uint8_t> out;
    put_u32le(out, plan.version);
    put_varint(out, plan.inputs.size());
    for (const TxPlan::In& in : plan.inputs) {
        put_outpoint(out, in);
        put_varint(out, 0); // empty scriptSig: witness money
        put_u32le(out, in.sequence);
    }
    put_outputs(out, plan);
    put_u32le(out, plan.locktime);
    return out;
}

TxPlan parse_skeleton(std::span<const uint8_t> bytes)
{
    Reader r { bytes };
    TxPlan plan;
    plan.version = r.u32();
    const uint64_t nin = r.varint();
    if (nin == 0 || nin > 1000)
        throw std::runtime_error("btc-tx: implausible input count");
    for (uint64_t i = 0; i < nin; ++i) {
        TxPlan::In in;
        const uint8_t* txid = r.take(32);
        for (int b = 0; b < 32; ++b)
            in.txid_be[std::size_t(b)] = txid[31 - b];
        in.vout = r.u32();
        if (r.varint() != 0)
            throw std::runtime_error("btc-tx: scriptSig on witness money");
        in.sequence = r.u32();
        plan.inputs.push_back(in);
    }
    const uint64_t nout = r.varint();
    if (nout == 0 || nout > 1000)
        throw std::runtime_error("btc-tx: implausible output count");
    for (uint64_t i = 0; i < nout; ++i) {
        TxPlan::Out o;
        o.value = r.u64();
        const uint64_t len = r.varint();
        if (len > 10000)
            throw std::runtime_error("btc-tx: implausible script");
        const uint8_t* s = r.take(std::size_t(len));
        o.script.assign(s, s + len);
        plan.outputs.push_back(std::move(o));
    }
    plan.locktime = r.u32();
    if (r.pos != bytes.size())
        throw std::runtime_error("btc-tx: trailing bytes");
    return plan;
}

std::array<uint8_t, 32> sighash_p2wpkh(const TxPlan& plan,
    std::size_t input_index, std::span<const uint8_t, 20> pubkey_hash160)
{
    if (input_index >= plan.inputs.size())
        throw std::invalid_argument("btc-tx: no such input");
    std::vector<uint8_t> buf;
    for (const TxPlan::In& in : plan.inputs)
        put_outpoint(buf, in);
    const auto hash_prevouts = sha256d(buf);
    buf.clear();
    for (const TxPlan::In& in : plan.inputs)
        put_u32le(buf, in.sequence);
    const auto hash_sequence = sha256d(buf);
    buf.clear();
    for (const TxPlan::Out& o : plan.outputs) {
        put_u64le(buf, o.value);
        put_varint(buf, o.script.size());
        buf.insert(buf.end(), o.script.begin(), o.script.end());
    }
    const auto hash_outputs = sha256d(buf);

    const TxPlan::In& in = plan.inputs[input_index];
    std::vector<uint8_t> pre;
    put_u32le(pre, plan.version);
    pre.insert(pre.end(), hash_prevouts.begin(), hash_prevouts.end());
    pre.insert(pre.end(), hash_sequence.begin(), hash_sequence.end());
    put_outpoint(pre, in);
    // scriptCode: the P2PKH form of the key, length-prefixed.
    pre.push_back(0x19);
    pre.push_back(0x76);
    pre.push_back(0xa9);
    pre.push_back(0x14);
    pre.insert(pre.end(), pubkey_hash160.begin(), pubkey_hash160.end());
    pre.push_back(0x88);
    pre.push_back(0xac);
    put_u64le(pre, in.value);
    put_u32le(pre, in.sequence);
    pre.insert(pre.end(), hash_outputs.begin(), hash_outputs.end());
    put_u32le(pre, plan.locktime);
    put_u32le(pre, 1); // SIGHASH_ALL
    return sha256d(pre);
}

std::array<uint8_t, 32> sighash_p2pkh(const TxPlan& plan,
    std::size_t input_index, std::span<const uint8_t, 20> pubkey_hash160)
{
    if (input_index >= plan.inputs.size())
        throw std::invalid_argument("btc-tx: no such input");
    // The whole transaction, with the spent output's script standing
    // in the signed input's slot and every other scriptSig empty.
    std::vector<uint8_t> pre;
    put_u32le(pre, plan.version);
    put_varint(pre, plan.inputs.size());
    for (std::size_t i = 0; i < plan.inputs.size(); ++i) {
        put_outpoint(pre, plan.inputs[i]);
        if (i == input_index) {
            pre.push_back(0x19);
            pre.push_back(0x76);
            pre.push_back(0xa9);
            pre.push_back(0x14);
            pre.insert(pre.end(), pubkey_hash160.begin(), pubkey_hash160.end());
            pre.push_back(0x88);
            pre.push_back(0xac);
        } else {
            put_varint(pre, 0);
        }
        put_u32le(pre, plan.inputs[i].sequence);
    }
    put_outputs(pre, plan);
    put_u32le(pre, plan.locktime);
    put_u32le(pre, 1); // SIGHASH_ALL
    return sha256d(pre);
}

std::array<uint8_t, 32> sighash_p2tr(const TxPlan& plan,
    std::size_t input_index, std::span<const uint8_t> own_script)
{
    if (input_index >= plan.inputs.size())
        throw std::invalid_argument("btc-tx: no such input");
    // BIP-341 hashes are single sha256, and the digest itself is a
    // tagged hash — taproot left double-sha behind.
    auto sha1 = [](std::span<const uint8_t> bytes) {
        std::array<uint8_t, 32> out;
        sha256_Raw(bytes.data(), bytes.size(), out.data());
        return out;
    };
    std::vector<uint8_t> buf;
    for (const TxPlan::In& in : plan.inputs)
        put_outpoint(buf, in);
    const auto sha_prevouts = sha1(buf);
    buf.clear();
    for (const TxPlan::In& in : plan.inputs)
        put_u64le(buf, in.value);
    const auto sha_amounts = sha1(buf);
    buf.clear();
    for (std::size_t i = 0; i < plan.inputs.size(); ++i) {
        put_varint(buf, own_script.size());
        buf.insert(buf.end(), own_script.begin(), own_script.end());
    }
    const auto sha_scripts = sha1(buf);
    buf.clear();
    for (const TxPlan::In& in : plan.inputs)
        put_u32le(buf, in.sequence);
    const auto sha_sequences = sha1(buf);
    buf.clear();
    for (const TxPlan::Out& o : plan.outputs) {
        put_u64le(buf, o.value);
        put_varint(buf, o.script.size());
        buf.insert(buf.end(), o.script.begin(), o.script.end());
    }
    const auto sha_outputs = sha1(buf);

    std::vector<uint8_t> msg;
    msg.push_back(0x00); // epoch
    msg.push_back(0x00); // SIGHASH_DEFAULT
    put_u32le(msg, plan.version);
    put_u32le(msg, plan.locktime);
    msg.insert(msg.end(), sha_prevouts.begin(), sha_prevouts.end());
    msg.insert(msg.end(), sha_amounts.begin(), sha_amounts.end());
    msg.insert(msg.end(), sha_scripts.begin(), sha_scripts.end());
    msg.insert(msg.end(), sha_sequences.begin(), sha_sequences.end());
    msg.insert(msg.end(), sha_outputs.begin(), sha_outputs.end());
    msg.push_back(0x00); // spend type: key path, no annex
    put_u32le(msg, uint32_t(input_index));

    uint8_t tag_hash[32];
    static constexpr char kTag[] = "TapSighash";
    sha256_Raw(
        reinterpret_cast<const uint8_t*>(kTag), sizeof kTag - 1, tag_hash);
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, tag_hash, 32);
    sha256_Update(&ctx, tag_hash, 32);
    sha256_Update(&ctx, msg.data(), msg.size());
    std::array<uint8_t, 32> out;
    sha256_Final(&ctx, out.data());
    return out;
}

std::vector<uint8_t> assemble_tx(
    const TxPlan& plan, std::span<const Witness> witnesses)
{
    if (witnesses.size() != plan.inputs.size())
        throw std::invalid_argument("btc-tx: a witness per input, exactly");
    const bool legacy = plan.spend == SpendKind::P2pkh;
    std::vector<uint8_t> out;
    put_u32le(out, plan.version);
    if (!legacy) {
        out.push_back(0x00); // segwit marker
        out.push_back(0x01); // flag
    }
    put_varint(out, plan.inputs.size());
    for (std::size_t i = 0; i < plan.inputs.size(); ++i) {
        put_outpoint(out, plan.inputs[i]);
        if (legacy) {
            // scriptSig: push(sig || hashtype) push(pubkey)
            const Witness& w = witnesses[i];
            put_varint(out, 1 + w.signature_der.size() + 1 + 1 + 33);
            out.push_back(uint8_t(w.signature_der.size() + 1));
            out.insert(
                out.end(), w.signature_der.begin(), w.signature_der.end());
            out.push_back(0x01);
            out.push_back(33);
            out.insert(out.end(), w.pubkey.begin(), w.pubkey.end());
        } else if (plan.spend == SpendKind::P2shP2wpkh) {
            // The one-push redeem: OP_0 push20 hash160(pubkey).
            uint8_t sha[32];
            sha256_Raw(
                witnesses[i].pubkey.data(), witnesses[i].pubkey.size(), sha);
            uint8_t h160[20];
            ripemd160(sha, sizeof sha, h160);
            put_varint(out, 23);
            out.push_back(22);
            out.push_back(0x00);
            out.push_back(0x14);
            out.insert(out.end(), h160, h160 + 20);
        } else {
            put_varint(out, 0);
        }
        put_u32le(out, plan.inputs[i].sequence);
    }
    put_outputs(out, plan);
    if (!legacy) {
        for (const Witness& w : witnesses) {
            if (plan.spend == SpendKind::P2tr) {
                // One item: the bare 64-byte schnorr signature —
                // SIGHASH_DEFAULT appends no type byte.
                put_varint(out, 1);
                put_varint(out, w.signature_der.size());
                out.insert(
                    out.end(), w.signature_der.begin(), w.signature_der.end());
                continue;
            }
            put_varint(out, 2);
            put_varint(out, w.signature_der.size() + 1);
            out.insert(
                out.end(), w.signature_der.begin(), w.signature_der.end());
            out.push_back(0x01); // SIGHASH_ALL rides the signature
            put_varint(out, w.pubkey.size());
            out.insert(out.end(), w.pubkey.begin(), w.pubkey.end());
        }
    }
    put_u32le(out, plan.locktime);
    return out;
}

std::string txid_of_signed(
    const TxPlan& plan, std::span<const Witness> witnesses)
{
    if (plan.spend != SpendKind::P2pkh)
        return txid_of(plan);
    const auto digest = sha256d(assemble_tx(plan, witnesses));
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i) {
        out[std::size_t(2 * i)] = kHex[digest[std::size_t(31 - i)] >> 4];
        out[std::size_t(2 * i + 1)] = kHex[digest[std::size_t(31 - i)] & 0xf];
    }
    return out;
}

std::string txid_of(const TxPlan& plan)
{
    const auto digest = sha256d(encode_skeleton(plan));
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i) {
        // Printed big-endian: the hash reversed.
        out[std::size_t(2 * i)] = kHex[digest[std::size_t(31 - i)] >> 4];
        out[std::size_t(2 * i + 1)] = kHex[digest[std::size_t(31 - i)] & 0xf];
    }
    return out;
}

uint64_t vsize_of(const TxPlan& plan, std::span<const Witness> witnesses)
{
    const std::size_t base = encode_skeleton(plan).size();
    const std::size_t total = assemble_tx(plan, witnesses).size();
    // weight = 3 x base + total; vsize rounds the weight up in quarters.
    return (3 * base + total + 3) / 4;
}

}
