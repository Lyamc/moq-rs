//! Pure-Rust HMAC / HKDF / AES-GCM for Quinn reset keys & tokens (no ring / no cc).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::{self, CryptoError};

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct PureHmacKey(HmacSha256);

impl PureHmacKey {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self(<HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key"))
    }
}

impl crypto::HmacKey for PureHmacKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        let mut mac = self.0.clone();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        out[..result.len()].copy_from_slice(&result);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut mac = self.0.clone();
        mac.update(data);
        mac.verify_slice(signature).map_err(|_| CryptoError)
    }
}

pub(crate) struct PureHandshakeTokenKey {
    prk: Hkdf<Sha256>,
}

impl PureHandshakeTokenKey {
    pub(crate) fn from_secret(secret: &[u8]) -> Self {
        Self {
            prk: Hkdf::<Sha256>::new(None, secret),
        }
    }
}

impl crypto::HandshakeTokenKey for PureHandshakeTokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let mut key_buffer = [0u8; 32];
        self.prk
            .expand(random_bytes, &mut key_buffer)
            .expect("HKDF expand");
        Box::new(PureAeadKey(
            Aes256Gcm::new_from_slice(&key_buffer).expect("AES key"),
        ))
    }
}

pub(crate) struct PureAeadKey(Aes256Gcm);

impl crypto::AeadKey for PureAeadKey {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let ct = self
            .0
            .encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: additional_data,
                },
            )
            .map_err(|_| CryptoError)?;
        *data = ct;
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let pt = self
            .0
            .decrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: additional_data,
                },
            )
            .map_err(|_| CryptoError)?;
        let n = pt.len();
        data[..n].copy_from_slice(&pt);
        Ok(&mut data[..n])
    }
}

/// AES-128-GCM for QUIC retry integrity tags (RFC 9001).
pub(crate) fn aes128_gcm_seal_tag(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8]) -> [u8; 16] {
    use aes_gcm::{Aes128Gcm, AeadInPlace};
    let cipher = Aes128Gcm::new_from_slice(key).unwrap();
    let n = Nonce::from_slice(nonce);
    let mut empty = Vec::new();
    let tag = cipher
        .encrypt_in_place_detached(n, aad, &mut empty)
        .unwrap();
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

pub(crate) fn aes128_gcm_open_tag(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], tag: &[u8]) -> bool {
    use aes_gcm::{Aes128Gcm, AeadInPlace, Tag};
    if tag.len() != 16 {
        return false;
    }
    let cipher = Aes128Gcm::new_from_slice(key).unwrap();
    let n = Nonce::from_slice(nonce);
    let t = Tag::from_slice(tag);
    let mut empty = Vec::new();
    cipher
        .decrypt_in_place_detached(n, aad, &mut empty, t)
        .is_ok()
}
