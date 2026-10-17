//! Server-side ("at rest") envelope encryption for shares with `enc_mode = server`.
//!
//! Each share gets a random DEK that encrypts the content with XChaCha20-Poly1305. The DEK is
//! wrapped with a KEK derived (HKDF-SHA256) from the master key, and, when the share has a
//! passphrase, also from argon2id(passphrase). Without the passphrase the content can't be
//! decrypted even by someone holding the database and master key.

use argon2::Argon2;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("wrong passphrase or corrupted data")]
    Decrypt,
    #[error("malformed encryption metadata")]
    Meta,
}

/// Stored in `shares.enc_meta` for server-mode shares.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerMeta {
    pub v: u8,
    /// nonce || ciphertext of the DEK.
    pub wrapped_dek: String,
    /// argon2id salt, present when a passphrase is mixed into the KEK.
    pub pw_salt: Option<String>,
}

fn derive_kek(master: &MasterKey, share_id: &str, passphrase: Option<(&str, &[u8])>) -> Result<[u8; 32], CryptoError> {
    let mut ikm = master.0.to_vec();
    if let Some((pw, salt)) = passphrase {
        let mut stretched = [0u8; 32];
        Argon2::default()
            .hash_password_into(pw.as_bytes(), salt, &mut stretched)
            .map_err(|_| CryptoError::Meta)?;
        ikm.extend_from_slice(&stretched);
    }
    let mut kek = [0u8; 32];
    Hkdf::<Sha256>::new(Some(share_id.as_bytes()), &ikm)
        .expand(b"sharesomething/kek/v1", &mut kek)
        .map_err(|_| CryptoError::Meta)?;
    Ok(kek)
}

fn seal_raw(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 24] = rand::random();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("encryption cannot fail");
    [nonce.as_slice(), &ct].concat()
}

fn open_raw(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 24 + 16 {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ct) = data.split_at(24);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Decrypt)
}

/// Encrypts `plaintext` for a share. CPU-heavy when a passphrase is given; call from `spawn_blocking`.
pub fn seal(master: &MasterKey, share_id: &str, plaintext: &[u8], passphrase: Option<&str>) -> (Vec<u8>, ServerMeta) {
    let dek: [u8; 32] = rand::random();
    let salt: Option<[u8; 16]> = passphrase.map(|_| rand::random());
    let kek = derive_kek(master, share_id, passphrase.zip(salt.as_ref().map(|s| s.as_slice()))).expect("valid argon2 params");
    let wrapped = seal_raw(&kek, format!("dek:{share_id}").as_bytes(), &dek);
    let ciphertext = seal_raw(&dek, share_id.as_bytes(), plaintext);
    (
        ciphertext,
        ServerMeta {
            v: 1,
            wrapped_dek: B64.encode(wrapped),
            pw_salt: salt.map(|s| B64.encode(s)),
        },
    )
}

/// Decrypts a share. Returns [`CryptoError::Decrypt`] on a wrong passphrase.
pub fn open(
    master: &MasterKey,
    share_id: &str,
    ciphertext: &[u8],
    meta: &ServerMeta,
    passphrase: Option<&str>,
) -> Result<Vec<u8>, CryptoError> {
    let salt = meta
        .pw_salt
        .as_deref()
        .map(|s| B64.decode(s).map_err(|_| CryptoError::Meta))
        .transpose()?;
    let pw = match (salt.as_deref(), passphrase) {
        (Some(salt), Some(pw)) => Some((pw, salt)),
        (Some(_), None) => return Err(CryptoError::Decrypt),
        (None, _) => None,
    };
    let kek = derive_kek(master, share_id, pw)?;
    let wrapped = B64.decode(&meta.wrapped_dek).map_err(|_| CryptoError::Meta)?;
    let dek: [u8; 32] = open_raw(&kek, format!("dek:{share_id}").as_bytes(), &wrapped)?
        .try_into()
        .map_err(|_| CryptoError::Meta)?;
    open_raw(&dek, share_id.as_bytes(), ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_without_passphrase() {
        let mk = MasterKey::new([7; 32]);
        let (ct, meta) = seal(&mk, "share-1", b"hello", None);
        assert_eq!(open(&mk, "share-1", &ct, &meta, None).unwrap(), b"hello");
        // Extra passphrase is ignored when none was set.
        assert_eq!(open(&mk, "share-1", &ct, &meta, Some("x")).unwrap(), b"hello");
    }

    #[test]
    fn passphrase_is_required_and_checked() {
        let mk = MasterKey::new([7; 32]);
        let (ct, meta) = seal(&mk, "s", b"secret", Some("correct horse"));
        assert_eq!(open(&mk, "s", &ct, &meta, Some("correct horse")).unwrap(), b"secret");
        assert!(matches!(open(&mk, "s", &ct, &meta, Some("wrong")), Err(CryptoError::Decrypt)));
        assert!(matches!(open(&mk, "s", &ct, &meta, None), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn bound_to_master_key_and_share_id() {
        let mk = MasterKey::new([7; 32]);
        let (ct, meta) = seal(&mk, "a", b"x", None);
        assert!(open(&MasterKey::new([8; 32]), "a", &ct, &meta, None).is_err());
        assert!(open(&mk, "b", &ct, &meta, None).is_err());
        let mut tampered = ct.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&mk, "a", &tampered, &meta, None).is_err());
    }
}
