// One confirmed Ethereum mainnet type-2 transaction, fields verbatim
// from eth_getTransactionByHash (ethereum-rpc.publicnode.com,
// 2026-07-18, block 0x185f194). Re-encoding them must keccak to
// kVecHash — mainnet consensus is the referee. Regen: fetch any
// confirmed type-0x2 tx with empty input and access list, paste the
// fields, done.
inline constexpr uint64_t kVecChainId = 1;
inline constexpr uint64_t kVecNonce = 0x9c15f;
inline constexpr const char* kVecMaxPriorityFee = "0x3b9aca00";
inline constexpr const char* kVecMaxFee = "0x80a0a374";
inline constexpr uint64_t kVecGas = 0x61a8;
inline constexpr const char* kVecTo
    = "6b2c6eaac28a749fe950c4ea9d9e56c16b63bce1";
inline constexpr const char* kVecValue = "0x5b845adf88be8";
inline constexpr uint8_t kVecYParity = 1;
inline constexpr const char* kVecR
    = "8feed7b56f5de1a37cf7dc6458ddbeff50129f889a3d5ba4349ee2d592253cb3";
inline constexpr const char* kVecS
    = "2fe8861efaeaa1618d64b77ac7c70f22107f6a7aab1f439bf2138987cb15c962";
inline constexpr const char* kVecHash
    = "97e82f647dfee1fe8613d3ca2e26e4afb2780926881e3bd5b06188133835435e";
inline constexpr uint64_t kVecBlock = 0x185f194;
