//! Shared AES-128-CBC primitives (PKCS7 padding) used by DLC, CCF and RSDF.
//!
//! Each format historically uses a different fixed key/IV pair. The actual
//! values live next to their format module; this file only exposes generic
//! helpers so the formats stay self-contained.
//!
//! Implementation uses `cipher`'s in-place `encrypt_padded_mut` / `decrypt_padded_mut`
//! to avoid pulling the optional `alloc` feature flag (the helpers below
//! manage their own `Vec` buffers).

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::error::PluginError;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const BLOCK: usize = 16;

pub fn aes128_cbc_encrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, PluginError> {
    let pt_len = plaintext.len();
    let buf_len = (pt_len / BLOCK + 1) * BLOCK;
    let mut buf = vec![0u8; buf_len];
    buf[..pt_len].copy_from_slice(plaintext);
    let ct_len = Aes128CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|e| PluginError::Decrypt(format!("encrypt: {}", e)))?
        .len();
    buf.truncate(ct_len);
    Ok(buf)
}

pub fn aes128_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PluginError> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK) {
        return Err(PluginError::Decrypt(
            "ciphertext length is not a multiple of 16".into(),
        ));
    }
    let mut buf = ciphertext.to_vec();
    let pt_len = Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| PluginError::Decrypt(e.to_string()))?
        .len();
    buf.truncate(pt_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_recovers_plaintext() {
        let key = *b"YELLOW SUBMARINE";
        let iv = *b"0123456789abcdef";
        let plaintext = b"https://example.com/file.zip";
        let cipher = aes128_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let recovered = aes128_cbc_decrypt(&key, &iv, &cipher).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_returns_error() {
        let key = *b"YELLOW SUBMARINE";
        let iv = *b"0123456789abcdef";
        let cipher = aes128_cbc_encrypt(&key, &iv, b"hello world!").unwrap();
        let wrong_key = *b"WRONG KEY 123456";
        let err = aes128_cbc_decrypt(&wrong_key, &iv, &cipher).unwrap_err();
        assert!(matches!(err, PluginError::Decrypt(_)));
    }

    #[test]
    fn ciphertext_length_is_multiple_of_block_size() {
        let key = *b"YELLOW SUBMARINE";
        let iv = *b"0123456789abcdef";
        let cipher = aes128_cbc_encrypt(&key, &iv, b"x").unwrap();
        assert_eq!(cipher.len() % BLOCK, 0);
        assert_eq!(cipher.len(), BLOCK);
    }

    #[test]
    fn empty_plaintext_yields_one_block() {
        let key = *b"YELLOW SUBMARINE";
        let iv = *b"0123456789abcdef";
        let cipher = aes128_cbc_encrypt(&key, &iv, b"").unwrap();
        assert_eq!(cipher.len(), BLOCK);
        let recovered = aes128_cbc_decrypt(&key, &iv, &cipher).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn decrypt_rejects_misaligned_input() {
        let key = *b"YELLOW SUBMARINE";
        let iv = *b"0123456789abcdef";
        let err = aes128_cbc_decrypt(&key, &iv, &[1, 2, 3]).unwrap_err();
        assert!(matches!(err, PluginError::Decrypt(_)));
    }
}
