//! Pure-Rust QUIC AES-128-GCM packet / header protection (no ring / no cc).
//!
//! Quinn requires `TLS13_AES_128_GCM_SHA256` with a non-`None` `quic` algorithm
//! for initial secrets (RFC 9001).

#![allow(clippy::duplicate_mod)]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray};
use aes::Aes128;
use aes_gcm::aead::KeyInit as GcmKeyInit;
use aes_gcm::{AeadInPlace, Aes128Gcm, Nonce as GcmNonce, Tag as GcmTag};
use rustls::crypto::cipher::{self, AeadKey, Iv};
use rustls::{quic, Error};

/// AES-ECB based header protection (RFC 9001 §5.4.1 / §5.4.3).
pub struct Aes128HeaderProtectionKey {
    key: Aes128,
}

impl Aes128HeaderProtectionKey {
    pub fn new(key: AeadKey) -> Self {
        Self {
            key: Aes128::new_from_slice(key.as_ref()).expect("AES-128 key length"),
        }
    }

    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        if sample.len() < 16 {
            return Err(Error::General("sample of invalid length".into()));
        }
        let mut block = GenericArray::clone_from_slice(&sample[..16]);
        self.key.encrypt_block(&mut block);
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        Ok(mask)
    }

    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        let mask = self.new_mask(sample)?;
        let (first_mask, pn_mask) = mask.split_first().unwrap();

        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = if *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            0x0f
        } else {
            0x1f
        };

        let first_plain = if masked {
            *first ^ (first_mask & bits)
        } else {
            *first
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }
        Ok(())
    }
}

impl quic::HeaderProtectionKey for Aes128HeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    #[inline]
    fn sample_len(&self) -> usize {
        16
    }
}

/// AES-128-GCM packet keys for QUIC.
pub struct Aes128GcmPacketKey {
    iv: Iv,
    crypto: Aes128Gcm,
}

impl Aes128GcmPacketKey {
    pub fn new(key: AeadKey, iv: Iv) -> Self {
        Self {
            iv,
            crypto: <Aes128Gcm as GcmKeyInit>::new_from_slice(key.as_ref()).expect("AES-GCM key"),
        }
    }
}

impl quic::PacketKey for Aes128GcmPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce_bytes = cipher::Nonce::new(&self.iv, packet_number).0;
        let nonce = GcmNonce::from_slice(&nonce_bytes);
        let tag = self
            .crypto
            .encrypt_in_place_detached(nonce, aad, payload)
            .map_err(|_| Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_ref()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let payload_len = payload.len();
        if payload_len < 16 {
            return Err(Error::DecryptError);
        }
        let (body, tag_bytes) = payload.split_at_mut(payload_len - 16);
        let nonce_bytes = cipher::Nonce::new(&self.iv, packet_number).0;
        let nonce = GcmNonce::from_slice(&nonce_bytes);
        let tag = GcmTag::from_slice(tag_bytes);
        self.crypto
            .decrypt_in_place_detached(nonce, aad, body, tag)
            .map_err(|_| Error::DecryptError)?;
        Ok(&payload[..payload_len - 16])
    }

    #[inline]
    fn tag_len(&self) -> usize {
        16
    }

    fn integrity_limit(&self) -> u64 {
        1 << 52
    }

    fn confidentiality_limit(&self) -> u64 {
        1 << 23
    }
}

pub struct Aes128GcmQuicAlgorithm;

impl quic::Algorithm for Aes128GcmQuicAlgorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(Aes128GcmPacketKey::new(key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(Aes128HeaderProtectionKey::new(key))
    }

    fn aead_key_len(&self) -> usize {
        16
    }
}

pub static AES_128_GCM_QUIC: Aes128GcmQuicAlgorithm = Aes128GcmQuicAlgorithm;
