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

/// XChaCha20-Poly1305 with a random nonce: returns nonce(24) || ciphertext.
pub fn seal_raw(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 24] = rand::random();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("encryption cannot fail");
    [nonce.as_slice(), &ct].concat()
}

pub fn open_raw(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < SEAL_OVERHEAD {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ct) = data.split_at(24);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Decrypt)
}

/// Bytes added by [`seal_raw`]: 24-byte nonce + 16-byte tag.
pub const SEAL_OVERHEAD: usize = 24 + 16;

pub type Dek = [u8; 32];

/// Encrypts `plaintext` for a share and returns the DEK too (needed to encrypt file chunks).
/// CPU-heavy when a passphrase is given; call from `spawn_blocking`.
pub fn seal(master: &MasterKey, share_id: &str, plaintext: &[u8], passphrase: Option<&str>) -> (Vec<u8>, ServerMeta, Dek) {
    let dek: Dek = rand::random();
    let salt: Option<[u8; 16]> = passphrase.map(|_| rand::random());
    let kek = derive_kek(master, share_id, passphrase.zip(salt.as_ref().map(|s| s.as_slice()))).expect("valid argon2 params");
    let wrapped = seal_raw(&kek, format!("dek:{share_id}").as_bytes(), &dek);
    let ciphertext = seal_raw(&dek, share_id.as_bytes(), plaintext);
    let meta = ServerMeta {
        v: 1,
        wrapped_dek: B64.encode(wrapped),
        pw_salt: salt.map(|s| B64.encode(s)),
    };
    (ciphertext, meta, dek)
}

/// Decrypts a share, returning the plaintext and the DEK. [`CryptoError::Decrypt`] means a wrong passphrase.
pub fn open(
    master: &MasterKey,
    share_id: &str,
    ciphertext: &[u8],
    meta: &ServerMeta,
    passphrase: Option<&str>,
) -> Result<(Vec<u8>, Dek), CryptoError> {
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
    let dek: Dek = open_raw(&kek, format!("dek:{share_id}").as_bytes(), &wrapped)?
        .try_into()
        .map_err(|_| CryptoError::Meta)?;
    Ok((open_raw(&dek, share_id.as_bytes(), ciphertext)?, dek))
}

/// Wraps a DEK under a bearer token (upload/download tokens), so the server can use the DEK
/// later without storing it in the clear or needing the passphrase again.
pub fn wrap_for_token(token: &str, share_id: &str, dek: &Dek) -> Vec<u8> {
    seal_raw(&token_key(token), format!("token:{share_id}").as_bytes(), dek)
}

pub fn unwrap_with_token(token: &str, share_id: &str, wrapped: &[u8]) -> Result<Dek, CryptoError> {
    open_raw(&token_key(token), format!("token:{share_id}").as_bytes(), wrapped)?
        .try_into()
        .map_err(|_| CryptoError::Meta)
}

fn token_key(token: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, token.as_bytes())
        .expand(b"sharesomething/token/v1", &mut k)
        .expect("valid length");
    k
}

/// AAD binding a file chunk to its share, file, position and finality (prevents reordering/truncation).
pub fn chunk_aad(share_id: &str, file_idx: u32, chunk: u32, last: bool) -> Vec<u8> {
    let mut aad = format!("chunk:{share_id}:").into_bytes();
    aad.extend_from_slice(&file_idx.to_be_bytes());
    aad.extend_from_slice(&chunk.to_be_bytes());
    aad.push(last as u8);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_without_passphrase() {
        let mk = MasterKey::new([7; 32]);
        let (ct, meta, _) = seal(&mk, "share-1", b"hello", None);
        assert_eq!(open(&mk, "share-1", &ct, &meta, None).unwrap().0, b"hello");
        // Extra passphrase is ignored when none was set.
        assert_eq!(open(&mk, "share-1", &ct, &meta, Some("x")).unwrap().0, b"hello");
    }

    #[test]
    fn passphrase_is_required_and_checked() {
        let mk = MasterKey::new([7; 32]);
        let (ct, meta, _) = seal(&mk, "s", b"secret", Some("correct horse"));
        assert_eq!(open(&mk, "s", &ct, &meta, Some("correct horse")).unwrap().0, b"secret");
        assert!(matches!(open(&mk, "s", &ct, &meta, Some("wrong")), Err(CryptoError::Decrypt)));
        assert!(matches!(open(&mk, "s", &ct, &meta, None), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn token_wrapping_and_chunks() {
        let mk = MasterKey::new([7; 32]);
        let (_, _, dek) = seal(&mk, "s", b"x", Some("pw"));
        let wrapped = wrap_for_token("tok", "s", &dek);
        assert_eq!(unwrap_with_token("tok", "s", &wrapped).unwrap(), dek);
        assert!(unwrap_with_token("other", "s", &wrapped).is_err());
        assert!(unwrap_with_token("tok", "t", &wrapped).is_err());
        let c = seal_raw(&dek, &chunk_aad("s", 0, 1, false), b"chunk");
        assert_eq!(c.len(), 5 + SEAL_OVERHEAD);
        assert!(
            open_raw(&dek, &chunk_aad("s", 0, 1, true), &c).is_err(),
            "finality is authenticated"
        );
        assert!(
            open_raw(&dek, &chunk_aad("s", 0, 2, false), &c).is_err(),
            "position is authenticated"
        );
        assert_eq!(open_raw(&dek, &chunk_aad("s", 0, 1, false), &c).unwrap(), b"chunk");
    }

    #[test]
    fn bound_to_master_key_and_share_id() {
        let mk = MasterKey::new([7; 32]);
        let (ct, meta, _) = seal(&mk, "a", b"x", None);
        assert!(open(&MasterKey::new([8; 32]), "a", &ct, &meta, None).is_err());
        assert!(open(&mk, "b", &ct, &meta, None).is_err());
        let mut tampered = ct.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&mk, "a", &tampered, &meta, None).is_err());
    }
}
