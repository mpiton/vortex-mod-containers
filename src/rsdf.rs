//! RSDF — RapidShare Download File container.
//!
//! Format (community-documented):
//!   * Plain text file, one line per encrypted URL.
//!   * Each line is hex-encoded AES-128-CBC ciphertext (PKCS7 padding).
//!   * Key and IV are fixed and identical (legacy RapidShare convention).
//!   * Lines may be CRLF or LF separated. Whitespace and empty lines ignored.
//!
//! See `docs/ADR-001-container-keys.md` for the rationale behind the embedded
//! key/IV values.

use crate::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt};
use crate::error::PluginError;
use crate::types::ContainerLink;

/// Historic RSDF AES-128 key (RapidShare legacy, public).
pub const RSDF_KEY: [u8; 16] = [
    0x8C, 0x35, 0x19, 0x2D, 0x96, 0x4D, 0xC3, 0x18, 0x2C, 0x6F, 0x84, 0xF3, 0x25, 0x22, 0x39, 0xEB,
];

/// IV equals the key in the legacy RSDF container, matching dcrypt-it / JD.
pub const RSDF_IV: [u8; 16] = RSDF_KEY;

pub fn looks_like_rsdf(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut saw_line = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !is_hex_block(trimmed) {
            return false;
        }
        saw_line = true;
    }
    saw_line
}

fn is_hex_block(s: &str) -> bool {
    if s.len() < 32 || !s.len().is_multiple_of(32) {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn decode(bytes: &[u8]) -> Result<Vec<ContainerLink>, PluginError> {
    let text = std::str::from_utf8(bytes)?;
    let mut links = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if !is_hex_block(line) {
            return Err(PluginError::Malformed(format!(
                "line {} is not a valid hex block",
                lineno + 1
            )));
        }
        let cipher_bytes = hex::decode(line)?;
        let plain = aes128_cbc_decrypt(&RSDF_KEY, &RSDF_IV, &cipher_bytes)?;
        let url = String::from_utf8(plain)?.trim().to_string();
        if url.is_empty() {
            continue;
        }
        links.push(ContainerLink {
            url,
            filename: None,
            size_bytes: None,
            mirrors: Vec::new(),
            checksums: Vec::new(),
        });
    }
    if links.is_empty() {
        return Err(PluginError::Malformed("no decrypted URLs".into()));
    }
    Ok(links)
}

/// Encrypt URLs back to RSDF wire format. Used by tests and the corpus
/// generator; the real Vortex flow only decrypts.
pub fn encode(urls: &[&str]) -> Result<String, PluginError> {
    let mut out = String::new();
    for url in urls {
        let cipher = aes128_cbc_encrypt(&RSDF_KEY, &RSDF_IV, url.as_bytes())?;
        out.push_str(&hex::encode_upper(&cipher));
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode_recovers_urls() {
        let urls = [
            "https://rapidshare.example/file1.zip",
            "https://rapidshare.example/file2.zip",
        ];
        let container = encode(&urls).unwrap();
        let links = decode(container.as_bytes()).unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].url, urls[0]);
        assert_eq!(links[1].url, urls[1]);
    }

    #[test]
    fn looks_like_rsdf_accepts_hex_lines() {
        let urls = ["https://example.com/a"];
        let container = encode(&urls).unwrap();
        assert!(looks_like_rsdf(container.as_bytes()));
    }

    #[test]
    fn looks_like_rsdf_rejects_xml() {
        assert!(!looks_like_rsdf(b"<?xml version=\"1.0\"?>"));
    }

    #[test]
    fn looks_like_rsdf_rejects_text_with_spaces() {
        assert!(!looks_like_rsdf(b"this is not hex\n"));
    }

    #[test]
    fn looks_like_rsdf_rejects_short_hex() {
        // 30 chars = 15 bytes, not a full AES block.
        assert!(!looks_like_rsdf(b"DEADBEEF12345678ABCDEF1234567A\n"));
    }

    #[test]
    fn looks_like_rsdf_rejects_empty() {
        assert!(!looks_like_rsdf(b""));
    }

    #[test]
    fn decode_skips_blank_lines_and_crlf() {
        let mut container = encode(&["https://example.com/a"]).unwrap();
        container = container.replace('\n', "\r\n");
        container.push_str("\r\n   \r\n");
        let links = decode(container.as_bytes()).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].url, "https://example.com/a");
    }

    #[test]
    fn decode_rejects_garbage_line() {
        let err = decode(b"NOTHEX\n").unwrap_err();
        assert!(matches!(err, PluginError::Malformed(_)));
    }

    #[test]
    fn decode_rejects_when_all_lines_decrypt_empty() {
        let cipher = aes128_cbc_encrypt(&RSDF_KEY, &RSDF_IV, b"   ").unwrap();
        let mut container = hex::encode_upper(&cipher);
        container.push('\n');
        let err = decode(container.as_bytes()).unwrap_err();
        assert!(matches!(err, PluginError::Malformed(_)));
    }
}
