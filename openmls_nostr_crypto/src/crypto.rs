use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, KeyInit,
};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use hpke::Hpke;
use hpke_rs_crypto::types as hpke_types;
use hpke_rs_nostr_crypto::HpkeNostrCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        self, AeadType, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
        HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, SignatureScheme,
    },
};
use rand::{RngCore, SeedableRng};
use secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::sync::RwLock;
use tls_codec::SecretVLBytes;

/// The `NostrCrypto` struct represents the cryptographic module used in the OpenMLS Nostr project.
pub struct NostrCrypto {
    rng: RwLock<rand_chacha::ChaCha20Rng>,
}

/// Implementation of the `Default` trait for `NostrCrypto`.
impl Default for NostrCrypto {
    /// Creates a new instance of `NostrCrypto` with default values.
    fn default() -> Self {
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
        }
    }
}

/// Error type for random number generation in `NostrCrypto`.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RandError {
    #[error("Rng lock is poisoned.")]
    LockPoisoned,
    #[error("Unable to collect enough randomness.")]
    NotEnoughRandomness,
}

/// Implementation of the `OpenMlsRand` trait for `NostrCrypto`.
impl OpenMlsRand for NostrCrypto {
    type Error = RandError;

    /// Generates a random array of bytes with a fixed length.
    ///
    /// # Arguments
    ///
    /// * `N` - The length of the array.
    ///
    /// # Errors
    ///
    /// Returns a `RandError::LockPoisoned` if the random number generator lock is poisoned.
    /// Returns a `RandError::NotEnoughRandomness` if there is not enough randomness available.
    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.rng.write().map_err(|_| Self::Error::LockPoisoned)?;
        let mut out = [0u8; N];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }

    /// Generates a random vector of bytes with a specified length.
    ///
    /// # Arguments
    ///
    /// * `len` - The length of the vector.
    ///
    /// # Errors
    ///
    /// Returns a `RandError::LockPoisoned` if the random number generator lock is poisoned.
    /// Returns a `RandError::NotEnoughRandomness` if there is not enough randomness available.
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.rng.write().map_err(|_| Self::Error::LockPoisoned)?;
        let mut out = vec![0u8; len];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }
}

#[inline(always)]
fn kem_mode(kem: HpkeKemType) -> hpke_types::KemAlgorithm {
    match kem {
        HpkeKemType::DhKem25519 => hpke_types::KemAlgorithm::DhKem25519,
        HpkeKemType::DhKemK256 => hpke_types::KemAlgorithm::DhKemK256,
        HpkeKemType::DhKemP256
        | HpkeKemType::DhKemP384
        | HpkeKemType::DhKemP521
        | HpkeKemType::DhKem448
        | HpkeKemType::XWingKemDraft2 => {
            unimplemented!("KemAlgorithm not supported by the NostrCrypto provider.")
        }
    }
}

#[inline(always)]
fn kdf_mode(kdf: HpkeKdfType) -> hpke_types::KdfAlgorithm {
    match kdf {
        HpkeKdfType::HkdfSha256 => hpke_types::KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 | HpkeKdfType::HkdfSha512 => {
            unimplemented!("KdfAlgorithm not supported by the NostrCrypto provider.")
        }
    }
}

#[inline(always)]
fn aead_mode(aead: HpkeAeadType) -> hpke_types::AeadAlgorithm {
    match aead {
        HpkeAeadType::AesGcm128 => hpke_types::AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::ChaCha20Poly1305 => hpke_types::AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::AesGcm256 | HpkeAeadType::Export => {
            unimplemented!("AeadAlgorithm not supported by the NostrCrypto provider.")
        }
    }
}

/// Implementation of the `OpenMlsCrypto` trait for `NostrCrypto`.
impl OpenMlsCrypto for NostrCrypto {
    fn supports(
        &self,
        ciphersuite: openmls_traits::types::Ciphersuite,
    ) -> Result<(), openmls_traits::types::CryptoError> {
        match ciphersuite {
            openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | openmls_traits::types::Ciphersuite::MLS_256_DHKEMK256_CHACHA20POLY1305_SHA256_K256 => {
                Ok(())
            }
            _ => Err(openmls_traits::types::CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<openmls_traits::types::Ciphersuite> {
        vec![
            openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            openmls_traits::types::Ciphersuite::MLS_256_DHKEMK256_CHACHA20POLY1305_SHA256_K256,
        ]
    }

    fn hkdf_extract(
        &self,
        hash_type: openmls_traits::types::HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
            _ => Err(openmls_traits::types::CryptoError::UnsupportedHashAlgorithm),
        }
    }

    fn hkdf_expand(
        &self,
        hash_type: openmls_traits::types::HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
            _ => Err(openmls_traits::types::CryptoError::UnsupportedHashAlgorithm),
        }
    }

    fn hash(
        &self,
        hash_type: openmls_traits::types::HashType,
        data: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
            _ => Err(openmls_traits::types::CryptoError::UnsupportedHashAlgorithm),
        }
    }

    fn aead_encrypt(
        &self,
        alg: openmls_traits::types::AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            _ => Err(CryptoError::UnsupportedAeadAlgorithm),
        }
    }

    fn aead_decrypt(
        &self,
        alg: openmls_traits::types::AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            _ => Err(CryptoError::UnsupportedAeadAlgorithm),
        }
    }

    fn signature_key_gen(
        &self,
        alg: openmls_traits::types::SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ED25519 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let sk = ed25519_dalek::SigningKey::generate(&mut *rng);
                let pk = sk.verifying_key().to_bytes().into();
                Ok((sk.to_bytes().into(), pk))
            }
            SignatureScheme::SCHNORR_SECP256K1_SHA256 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let secp = Secp256k1::new();
                let (k, pk) = secp.generate_keypair(&mut *rng);
                Ok((k.as_ref().to_vec(), pk.serialize().to_vec()))
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn verify_signature(
        &self,
        alg: openmls_traits::types::SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::VerifyingKey::try_from(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(CryptoError::CryptoLibraryError);
                }
                let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                sig.clone_from_slice(signature);
                k.verify_strict(data, &ed25519_dalek::Signature::from(sig))
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::SCHNORR_SECP256K1_SHA256 => {
                let secp = Secp256k1::new();
                let xok =
                    XOnlyPublicKey::from_slice(pk).map_err(|_| CryptoError::CryptoLibraryError)?;
                let message = Message::from_digest_slice(data)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let sig = Signature::from_slice(signature)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                secp.verify_schnorr(&sig, &message, &xok)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(
        &self,
        alg: openmls_traits::types::SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::try_from(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = k.sign(data);
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::SCHNORR_SECP256K1_SHA256 => {
                let secp = Secp256k1::new();
                let k = SecretKey::from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                let keypair = Keypair::from_secret_key(&secp, &k);
                let message = Message::from_digest_slice(data)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = secp.sign_schnorr(&message, &keypair);
                Ok(signature.as_ref().to_vec())
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<types::HpkeCiphertext, CryptoError> {
        let (kem_output, ciphertext) = hpke_from_config(config)
            .seal(&pk_r.into(), info, aad, ptxt, None, None, None)
            .map_err(|e| match e {
                hpke::HpkeError::InvalidInput => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })?;
        Ok(HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke_from_config(config)
            .open(
                input.kem_output.as_slice(),
                &sk_r.into(),
                info,
                aad,
                input.ciphertext.as_slice(),
                None,
                None,
                None,
            )
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        let (kem_output, context) = hpke_from_config(config)
            .setup_sender(&pk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::SenderSetupError)?;
        let exported_secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok((kem_output, exported_secret.into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let context = hpke_from_config(config)
            .setup_receiver(enc, &sk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::ReceiverSetupError)?;
        let exported_secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok(exported_secret.into())
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<types::HpkeKeyPair, CryptoError> {
        let kp = hpke_from_config(config)
            .derive_key_pair(ikm)
            .map_err(|e| match e {
                hpke::HpkeError::InvalidInput => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })?
            .into_keys();
        Ok(HpkeKeyPair {
            private: kp.0.as_slice().into(),
            public: kp.1.as_slice().into(),
        })
    }
}

fn hpke_from_config(config: HpkeConfig) -> Hpke<HpkeNostrCrypto> {
    Hpke::<HpkeNostrCrypto>::new(
        hpke::Mode::Base,
        kem_mode(config.0),
        kdf_mode(config.1),
        aead_mode(config.2),
    )
}
