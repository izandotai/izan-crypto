// BIP-84 official test vectors (P2WPKH addresses), vendored from
// bitcoin/bips bip-0084.mediawiki. Regenerate per tests/data/regen.md.

static constexpr const char* kBip84Mnemonic
    = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

struct Bip84Vector {
    const char* path;
    const char* address;
};

static constexpr Bip84Vector kBip84Vectors[] = {
    { "m/84'/0'/0'/0/0", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" },
    { "m/84'/0'/0'/0/1", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g" },
    { "m/84'/0'/0'/1/0", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el" },
};
