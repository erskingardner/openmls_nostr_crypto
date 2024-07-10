//! # OpenMLS Nostr Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS.

use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;

mod crypto;
pub use crypto::*;

#[derive(Default)]
pub struct NostrProvider {
    crypto: crypto::NostrCrypto,
    rand: crypto::NostrCrypto,
    key_store: MemoryStorage,
}

impl OpenMlsProvider for NostrProvider {
    type CryptoProvider = crypto::NostrCrypto;
    type RandProvider = crypto::NostrCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
}
