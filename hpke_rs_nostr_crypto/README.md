# HPKE RS Nostr Crypto

This library implements the [HPKE RS Crypto traits](https://docs.rs/hpke-rs-crypto/latest/hpke_rs_crypto/) focused on using only the bare minimum of features and ciphersuites and use the Bitcoin/Nostr-standard [secp256k1 crate](https://github.com/rust-bitcoin/rust-secp256k1/) instead of the default RustCrypto crate used by OpenMLS.

## Supported Ciphersuites

- [x] MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
- [x] MLS_256_DHKEMK256_CHACHA20POLY1305_SHA256_K256