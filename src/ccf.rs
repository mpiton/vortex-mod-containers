//! CCF — Cryptload Container Format.
//!
//! Cryptload is the legacy German download manager whose container format
//! pre-dates JDownloader's DLC. The on-disk layout supported by this module
//! is the v1 community-documented variant:
//!
//! ```text
//! "CCF1\n" magic
//! base64(AES-128-CBC(inner_xml))
//! ```
//!
//! `inner_xml` mirrors the DLC v1 layout (a `<package>` of `<file>` entries)
//! and uses Cryptload-distinct AES key/IV — see
//! `docs/ADR-001-container-keys.md` for the rationale and roadmap towards
//! supporting Cryptload v2/v3 captures once reverse-engineered.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt};
use crate::error::PluginError;
use crate::types::ContainerLink;

pub const CCF_MAGIC: &str = "CCF1\n";
pub const CCF_KEY: [u8; 16] = *b"v0rt3xCryptL0adC";
pub const CCF_IV: [u8; 16] = *b"CcfVortexInitVec";

pub fn looks_like_ccf(bytes: &[u8]) -> bool {
    bytes.starts_with(CCF_MAGIC.as_bytes())
}

pub fn decode(bytes: &[u8]) -> Result<Vec<ContainerLink>, PluginError> {
    if !looks_like_ccf(bytes) {
        return Err(PluginError::Malformed("missing CCF magic".into()));
    }
    let body = &bytes[CCF_MAGIC.len()..];
    let body_str = std::str::from_utf8(body)?.trim();
    let cipher = B64.decode(body_str.replace(['\n', '\r'], ""))?;
    let inner_plain = aes128_cbc_decrypt(&CCF_KEY, &CCF_IV, &cipher)?;
    let inner_str = std::str::from_utf8(&inner_plain)?;
    parse_inner(inner_str)
}

fn parse_inner(xml: &str) -> Result<Vec<ContainerLink>, PluginError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut links = Vec::new();
    let mut current: Option<InnerFile> = None;
    let mut active: Option<Field> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(e) => match e.name().as_ref() {
                b"file" => current = Some(InnerFile::default()),
                b"url" => active = Some(Field::Url),
                b"name" => active = Some(Field::Name),
                b"size" => active = Some(Field::Size),
                _ => {}
            },
            Event::End(e) => match e.name().as_ref() {
                b"file" => {
                    if let Some(f) = current.take() {
                        links.push(f.finalise()?);
                    }
                }
                b"url" | b"name" | b"size" => active = None,
                _ => {}
            },
            Event::Text(t) => {
                let owned = t.unescape()?.into_owned();
                let trimmed = owned.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match (active, current.as_mut()) {
                    (Some(Field::Url), Some(f)) => f.url = Some(trimmed.to_string()),
                    (Some(Field::Name), Some(f)) => f.name = Some(trimmed.to_string()),
                    (Some(Field::Size), Some(f)) => f.size = trimmed.parse::<u64>().ok(),
                    _ => {}
                }
            }
            _ => {}
        }
        buf.clear();
    }

    if links.is_empty() {
        return Err(PluginError::Malformed("CCF has no <file>".into()));
    }
    Ok(links)
}

#[derive(Default)]
struct InnerFile {
    url: Option<String>,
    name: Option<String>,
    size: Option<u64>,
}

impl InnerFile {
    fn finalise(self) -> Result<ContainerLink, PluginError> {
        let url = self.url.ok_or(PluginError::MissingField("url"))?;
        Ok(ContainerLink {
            url,
            filename: self.name,
            size_bytes: self.size,
            mirrors: Vec::new(),
            checksums: Vec::new(),
        })
    }
}

#[derive(Clone, Copy)]
enum Field {
    Url,
    Name,
    Size,
}

pub fn encode(entries: &[(&str, Option<&str>, Option<u64>)]) -> Result<Vec<u8>, PluginError> {
    let mut inner = String::from("<package>");
    for (url, name, size) in entries {
        inner.push_str("<file>");
        inner.push_str("<url>");
        inner.push_str(&xml_escape(url));
        inner.push_str("</url>");
        if let Some(n) = name {
            inner.push_str("<name>");
            inner.push_str(&xml_escape(n));
            inner.push_str("</name>");
        }
        if let Some(s) = size {
            inner.push_str(&format!("<size>{}</size>", s));
        }
        inner.push_str("</file>");
    }
    inner.push_str("</package>");

    let cipher = aes128_cbc_encrypt(&CCF_KEY, &CCF_IV, inner.as_bytes())?;
    let mut out = CCF_MAGIC.as_bytes().to_vec();
    out.extend_from_slice(B64.encode(&cipher).as_bytes());
    Ok(out)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(&'static str, Option<&'static str>, Option<u64>)> {
        vec![
            (
                "https://cryptload.example/a.rar",
                Some("archive.rar"),
                Some(2_000_000),
            ),
            ("https://cryptload.example/b.rar", None, None),
        ]
    }

    #[test]
    fn encode_then_decode_recovers_links() {
        let blob = encode(&entries()).unwrap();
        let links = decode(&blob).unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].url, "https://cryptload.example/a.rar");
        assert_eq!(links[0].filename.as_deref(), Some("archive.rar"));
        assert_eq!(links[0].size_bytes, Some(2_000_000));
        assert_eq!(links[1].url, "https://cryptload.example/b.rar");
    }

    #[test]
    fn looks_like_ccf_recognises_magic() {
        let blob = encode(&entries()).unwrap();
        assert!(looks_like_ccf(&blob));
    }

    #[test]
    fn looks_like_ccf_rejects_no_magic() {
        assert!(!looks_like_ccf(b"<dlc>...</dlc>"));
        assert!(!looks_like_ccf(b""));
    }

    #[test]
    fn decode_rejects_when_magic_missing() {
        let err = decode(b"random data").unwrap_err();
        assert!(matches!(err, PluginError::Malformed(_)));
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        let mut blob = CCF_MAGIC.as_bytes().to_vec();
        blob.extend_from_slice(b"!!!not base64!!!");
        let err = decode(&blob).unwrap_err();
        assert!(matches!(err, PluginError::Base64(_)));
    }

    #[test]
    fn decode_rejects_zero_files_after_decrypt() {
        let inner = "<package></package>";
        let cipher = aes128_cbc_encrypt(&CCF_KEY, &CCF_IV, inner.as_bytes()).unwrap();
        let mut blob = CCF_MAGIC.as_bytes().to_vec();
        blob.extend_from_slice(B64.encode(&cipher).as_bytes());
        let err = decode(&blob).unwrap_err();
        assert!(matches!(err, PluginError::Malformed(_)));
    }

    #[test]
    fn xml_escape_handles_special_chars() {
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
    }

    #[test]
    fn encode_escapes_url_with_ampersand() {
        let entries = vec![("https://x.example/?a=1&b=2", None, None)];
        let blob = encode(&entries).unwrap();
        let links = decode(&blob).unwrap();
        assert_eq!(links[0].url, "https://x.example/?a=1&b=2");
    }
}
