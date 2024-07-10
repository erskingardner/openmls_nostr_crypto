extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt::Display;

use hpke_rs_crypto::{
    error::Error,
    types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    CryptoRng, HpkeCrypto, HpkeTestRng, RngCore,
};

use rand_chacha::{rand_core, ChaCha20Rng};
use secp256k1::{ecdh::SharedSecret, rand::SeedableRng, PublicKey, Secp256k1, SecretKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

mod aead;
mod hkdf;
use crate::aead::*;
use crate::hkdf::*;

// The Nostr Crypto HPKE Provider
#[derive(Debug)]
pub struct HpkeNostrCrypto {}

// The PRNG for the Nostr Crypto HPKE Provider
pub struct HpkeNostrCryptoPrng {
    rng: ChaCha20Rng,
}

impl HpkeCrypto for HpkeNostrCrypto {
    type HpkePrng = HpkeNostrCryptoPrng;

    fn prng() -> Self::HpkePrng {
        HpkeNostrCryptoPrng {
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    fn name() -> String {
        "NostrCrypto".into()
    }

    fn kdf_extract(alg: KdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match alg {
            KdfAlgorithm::HkdfSha256 => sha256_extract(salt, ikm),
            KdfAlgorithm::HkdfSha384 => sha384_extract(salt, ikm),
            KdfAlgorithm::HkdfSha512 => sha512_extract(salt, ikm),
        }
    }

    fn kdf_expand(
        alg: hpke_rs_crypto::types::KdfAlgorithm,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, Error> {
        match alg {
            KdfAlgorithm::HkdfSha256 => sha256_expand(prk, info, output_size),
            KdfAlgorithm::HkdfSha384 => sha384_expand(prk, info, output_size),
            KdfAlgorithm::HkdfSha512 => sha512_expand(prk, info, output_size),
        }
    }

    fn kem_key_gen(alg: KemAlgorithm, prng: &mut Self::HpkePrng) -> Result<Vec<u8>, Error> {
        let rng = &mut prng.rng;
        match alg {
            KemAlgorithm::DhKem25519 => Ok(X25519StaticSecret::random_from_rng(&mut *rng)
                .to_bytes()
                .to_vec()),
            KemAlgorithm::DhKemK256 => Ok(SecretKey::new(&mut *rng).as_ref().to_vec()),
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn kem_validate_sk(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        match alg {
            KemAlgorithm::DhKemK256 => SecretKey::from_slice(sk)
                .map_err(|_| Error::KemInvalidSecretKey)
                .map(|_| sk.to_vec()),
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn kem_derive_base(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        match alg {
            KemAlgorithm::DhKem25519 => {
                if sk.len() != 32 {
                    return Err(Error::KemInvalidSecretKey);
                }
                assert!(sk.len() == 32);
                let sk_array: [u8; 32] = sk.try_into().map_err(|_| Error::KemInvalidSecretKey)?;
                let sk = X25519StaticSecret::from(sk_array);
                Ok(X25519PublicKey::from(&sk).as_bytes().to_vec())
            }
            KemAlgorithm::DhKemK256 => {
                let secp = Secp256k1::new();
                let sk = SecretKey::from_slice(sk).map_err(|_| Error::KemInvalidSecretKey)?;
                Ok(sk.public_key(&secp).serialize().to_vec())
            }
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn kem_derive(alg: KemAlgorithm, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
        match alg {
            KemAlgorithm::DhKem25519 => {
                if sk.len() != 32 {
                    return Err(Error::KemInvalidSecretKey);
                }
                if pk.len() != 32 {
                    return Err(Error::KemInvalidPublicKey);
                }
                assert!(pk.len() == 32);
                assert!(sk.len() == 32);
                let sk_array: [u8; 32] = sk.try_into().map_err(|_| Error::KemInvalidSecretKey)?;
                let pk_array: [u8; 32] = pk.try_into().map_err(|_| Error::KemInvalidPublicKey)?;
                let sk = X25519StaticSecret::from(sk_array);
                Ok(sk
                    .diffie_hellman(&X25519PublicKey::from(pk_array))
                    .as_bytes()
                    .to_vec())
            }
            KemAlgorithm::DhKemK256 => {
                let sk = SecretKey::from_slice(sk).map_err(|_| Error::KemInvalidSecretKey)?;
                let pk = PublicKey::from_slice(pk).map_err(|_| Error::KemInvalidPublicKey)?;
                Ok(SharedSecret::new(&pk, &sk).secret_bytes().to_vec())
            }
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn aead_seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match alg {
            AeadAlgorithm::Aes128Gcm => aes128_seal(key, nonce, aad, msg),
            AeadAlgorithm::ChaCha20Poly1305 => chacha_seal(key, nonce, aad, msg),
            _ => Err(Error::UnknownAeadAlgorithm),
        }
    }

    fn aead_open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match alg {
            AeadAlgorithm::Aes128Gcm => aes128_open(alg, key, nonce, aad, msg),
            AeadAlgorithm::ChaCha20Poly1305 => chacha_open(alg, key, nonce, aad, msg),
            _ => Err(Error::UnknownAeadAlgorithm),
        }
    }

    /// Returns an error if the KDF algorithm is not supported by this crypto provider.
    fn supports_kdf(alg: hpke_rs_crypto::types::KdfAlgorithm) -> Result<(), Error> {
        match alg {
            KdfAlgorithm::HkdfSha256 => Ok(()),
            _ => Err(Error::UnknownKdfAlgorithm),
        }
    }

    /// Returns an error if the KEM algorithm is not supported by this crypto provider.
    fn supports_kem(alg: hpke_rs_crypto::types::KemAlgorithm) -> Result<(), Error> {
        match alg {
            KemAlgorithm::DhKem25519 | KemAlgorithm::DhKemK256 => Ok(()),
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    /// Returns an error if the AEAD algorithm is not supported by this crypto provider.
    fn supports_aead(alg: AeadAlgorithm) -> Result<(), Error> {
        match alg {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::ChaCha20Poly1305 => Ok(()),
            _ => Err(Error::UnknownAeadAlgorithm),
        }
    }
}

impl RngCore for HpkeNostrCryptoPrng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for HpkeNostrCryptoPrng {}

impl HpkeTestRng for HpkeNostrCryptoPrng {
    fn try_fill_test_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest)
    }

    fn seed(&mut self, _: &[u8]) {}
}

impl Display for HpkeNostrCrypto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Self::name())
    }
}
