#include "domain/tx/eip1559.hpp"

#include <stdexcept>

extern "C" {
#include <sha3.h>
}

#include "core/codec/rlp.hpp"

namespace izan::tx {

namespace {

    using codec::rlp_bytes;
    using codec::rlp_list;
    using codec::rlp_uint;

    // The nine unsigned fields, in wire order.
    std::vector<std::vector<uint8_t>> base_fields(const Eip1559Tx& tx)
    {
        if (tx.chain_id == 0)
            throw std::invalid_argument("eip1559: chain_id 0");
        if (tx.gas_limit == 0)
            throw std::invalid_argument("eip1559: gas_limit 0");
        std::vector<std::vector<uint8_t>> f;
        f.push_back(rlp_uint(tx.chain_id));
        f.push_back(rlp_uint(tx.nonce));
        f.push_back(rlp_uint(tx.max_priority_fee_per_gas));
        f.push_back(rlp_uint(tx.max_fee_per_gas));
        f.push_back(rlp_uint(tx.gas_limit));
        f.push_back(rlp_bytes(tx.to));
        f.push_back(rlp_uint(tx.value));
        f.push_back(rlp_bytes(tx.data));
        static const std::vector<std::vector<uint8_t>> kNoAccessList;
        f.push_back(rlp_list(kNoAccessList)); // always empty in v1
        return f;
    }

    std::vector<uint8_t> typed_envelope(
        const std::vector<std::vector<uint8_t>>& fields)
    {
        std::vector<uint8_t> out { 0x02 };
        const std::vector<uint8_t> body = rlp_list(fields);
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }

}

std::vector<uint8_t> signing_payload(const Eip1559Tx& tx)
{
    return typed_envelope(base_fields(tx));
}

std::array<uint8_t, 32> signing_hash(const Eip1559Tx& tx)
{
    const std::vector<uint8_t> payload = signing_payload(tx);
    std::array<uint8_t, 32> digest {};
    keccak_256(payload.data(), payload.size(), digest.data());
    return digest;
}

std::vector<uint8_t> encode_signed(const Eip1559Tx& tx, uint8_t y_parity,
    std::span<const uint8_t, 32> r, std::span<const uint8_t, 32> s)
{
    if (y_parity > 1)
        throw std::invalid_argument("eip1559: y_parity must be 0/1");
    auto strip = [](std::span<const uint8_t, 32> v) {
        std::size_t first = 0;
        while (first < 32 && v[first] == 0)
            ++first;
        return rlp_bytes(v.subspan(first));
    };
    std::vector<std::vector<uint8_t>> f = base_fields(tx);
    f.push_back(rlp_uint(uint64_t(y_parity)));
    f.push_back(strip(r));
    f.push_back(strip(s));
    return typed_envelope(f);
}

std::array<uint8_t, 32> tx_hash(std::span<const uint8_t> raw)
{
    std::array<uint8_t, 32> digest {};
    keccak_256(raw.data(), raw.size(), digest.data());
    return digest;
}

}
