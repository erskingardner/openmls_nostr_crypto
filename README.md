# OpenMLS Nostr Crypto



These crates are Nostr-centric implementations of the traits required for the [OpenMLS library](https://github.com/openmls/openmls).

These traits are implemented with the bare minimum of features and ciphersuites and use the Bitcoin/Nostr-standard [secp256k1 crate](https://github.com/rust-bitcoin/rust-secp256k1/) instead of the default RustCrypto crate used by OpenMLS.

This library implements the following traits 

- [OpenMLS traits](https://github.com/openmls/openmls)
- [HPKE RS Crypto traits](https://docs.rs/hpke-rs-crypto/latest/hpke_rs_crypto/)

## Supported MLS Ciphersuites

Read more about the MLS ciphersuites in the [spec here](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.1). 

- [x] MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (Required by MLS spec)
- [x] MLS_256_DHKEMK256_CHACHA20POLY1305_SHA256_K256 (Nostr specific)

The `MLS_256_DHKEMK256_CHACHA20POLY1305_SHA256_K256` ciphersuite is a custom/private ciphersuite that isn't part of the official spec. This repo is a work in progress while adding the secp256k1 curve to various dependent libraries and the upstream OpenMLS library itself.

## NIP-104

TODO

## Contributing

TODO