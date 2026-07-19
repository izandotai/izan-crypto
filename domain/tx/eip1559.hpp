#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "core/units/u256.hpp"

namespace izan::tx {

// A type-2 (EIP-1559) transaction. v1 scope: transfers and contract
// calls — `to` is always present (contract creation is not a wallet
// operation) and the access list is always empty.
struct Eip1559Tx {
    uint64_t chain_id = 0;
    uint64_t nonce = 0;
    units::U256 max_priority_fee_per_gas;
    units::U256 max_fee_per_gas;
    uint64_t gas_limit = 0;
    std::array<uint8_t, 20> to {};
    units::U256 value;
    std::vector<uint8_t> data;
};

// 0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gas, to, value,
// data, accessList]) — the bytes whose keccak the signer signs.
std::vector<uint8_t> signing_payload(const Eip1559Tx& tx);
std::array<uint8_t, 32> signing_hash(const Eip1559Tx& tx);

// 0x02 || rlp([..., yParity, r, s]) — the raw transaction for
// eth_sendRawTransaction. r/s are minimal-integer encoded per RLP.
std::vector<uint8_t> encode_signed(const Eip1559Tx& tx, uint8_t y_parity,
    std::span<const uint8_t, 32> r, std::span<const uint8_t, 32> s);

// keccak of the raw bytes = the transaction hash explorers show.
std::array<uint8_t, 32> tx_hash(std::span<const uint8_t> raw);

}
