//! DLC — Download Link Container.
//!
//! The wire format used here is the legacy JDownloader-compatible v1 layout:
//!
//! ```text
//! base64(
//!   <dlc>
//!     <header>...</header>
//!     <content>base64(AES-128-CBC(inner_xml))</content>
//!   </dlc>
//! )
//! ```
//!
//! `inner_xml` lists `<file>` entries with base64-encoded `<url>`, optional
//! base64-encoded `<filename>` and a numeric `<size>`. AES key/IV are the
//! historic JD constants (see `docs/ADR-001-container-keys.md`).
//!
//! Newer JDownloader DLCs (v3) request a per-file key from
//! `service.jdownloader.org` over TLS; that path is intentionally not
//! implemented — the plugin keeps the privacy surface zero by refusing to
//! call third-party services. v3 containers therefore fail with a clear
//! error and surface to the UI as "unsupported DLC variant".

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt};
use crate::error::PluginError;
use crate::types::ContainerLink;
use crate::xml::{decode_reference, decode_text};

/// Historic DLC v1 key (JDownloader, public).
pub const DLC_KEY: [u8; 16] = *b"cb99b5cbc24db398";
/// Historic DLC v1 IV (JDownloader, public).
pub const DLC_IV: [u8; 16] = *b"9bc24cb995cb98b3";

const MIN_BASE64_LEN: usize = 32;

pub fn looks_like_dlc(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let trimmed = text.trim();
    if trimmed.len() < MIN_BASE64_LEN {
        return false;
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '\n' | '\r'))
    {
        return false;
    }
    let Ok(decoded) = B64.decode(trimmed.replace(['\n', '\r'], "")) else {
        return false;
    };
    let Ok(decoded_str) = std::str::from_utf8(&decoded) else {
        return false;
    };
    decoded_str.contains("<dlc") && decoded_str.contains("<content>")
}

pub fn decode(bytes: &[u8]) -> Result<Vec<ContainerLink>, PluginError> {
    let text = std::str::from_utf8(bytes)?.trim();
    let outer_xml = B64.decode(text.replace(['\n', '\r'], ""))?;
    let outer_str = std::str::from_utf8(&outer_xml)?;
    let content_b64 = extract_content(outer_str)?;
    let cipher = B64.decode(content_b64.trim())?;
    let inner_plain = aes128_cbc_decrypt(&DLC_KEY, &DLC_IV, &cipher)?;
    let inner_str = std::str::from_utf8(&inner_plain)?;
    parse_inner(inner_str)
}

fn extract_content(xml: &str) -> Result<String, PluginError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_content = false;
    let mut text = String::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(e) if e.name().as_ref() == b"content" => in_content = true,
            Event::End(e) if e.name().as_ref() == b"content" => in_content = false,
            Event::Text(t) if in_content => text.push_str(&decode_text(&t)?),
            Event::CData(c) if in_content => {
                text.push_str(std::str::from_utf8(c.into_inner().as_ref())?)
            }
            Event::GeneralRef(reference) if in_content => {
                text.push_str(&decode_reference(&reference)?)
            }
            _ => {}
        }
        buf.clear();
    }
    if text.trim().is_empty() {
        return Err(PluginError::MissingField("content"));
    }
    Ok(text)
}

fn parse_inner(xml: &str) -> Result<Vec<ContainerLink>, PluginError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut links = Vec::new();
    let mut current: Option<InnerFile> = None;
    let mut active_field: Option<InnerField> = None;
    let mut field_text = String::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(e) => match e.name().as_ref() {
                b"file" => current = Some(InnerFile::default()),
                b"url" => {
                    active_field = Some(InnerField::Url);
                    field_text.clear();
                }
                b"filename" => {
                    active_field = Some(InnerField::Filename);
                    field_text.clear();
                }
                b"size" => {
                    active_field = Some(InnerField::Size);
                    field_text.clear();
                }
                _ => {}
            },
            Event::End(e) => match e.name().as_ref() {
                b"file" => {
                    if let Some(file) = current.take() {
                        links.push(file.finalise()?);
                    }
                }
                b"url" | b"filename" | b"size" => {
                    let trimmed = field_text.trim();
                    match (active_field, current.as_mut()) {
                        (Some(InnerField::Url), Some(file)) => {
                            let plain = B64.decode(trimmed)?;
                            file.url = Some(String::from_utf8(plain)?);
                        }
                        (Some(InnerField::Filename), Some(file)) if !trimmed.is_empty() => {
                            let plain = B64.decode(trimmed)?;
                            file.filename = Some(String::from_utf8(plain)?);
                        }
                        (Some(InnerField::Size), Some(file)) => {
                            file.size = trimmed.parse::<u64>().ok();
                        }
                        _ => {}
                    }
                    active_field = None;
                    field_text.clear();
                }
                _ => {}
            },
            Event::Text(t) if active_field.is_some() => field_text.push_str(&decode_text(&t)?),
            Event::CData(c) if active_field.is_some() => field_text.push_str(&c.decode()?),
            Event::GeneralRef(reference) if active_field.is_some() => {
                field_text.push_str(&decode_reference(&reference)?)
            }
            _ => {}
        }
        buf.clear();
    }

    if links.is_empty() {
        return Err(PluginError::Malformed("DLC has no <file>".into()));
    }
    Ok(links)
}

#[derive(Default)]
struct InnerFile {
    url: Option<String>,
    filename: Option<String>,
    size: Option<u64>,
}

impl InnerFile {
    fn finalise(self) -> Result<ContainerLink, PluginError> {
        let url = self
            .url
            .filter(|url| !url.trim().is_empty())
            .ok_or(PluginError::MissingField("url"))?;
        Ok(ContainerLink {
            url,
            filename: self.filename,
            size_bytes: self.size,
            mirrors: Vec::new(),
            checksums: Vec::new(),
        })
    }
}

#[derive(Clone, Copy)]
enum InnerField {
    Url,
    Filename,
    Size,
}

/// Encode a list of files into a DLC v1 container. Used by tests + corpus.
pub fn encode(entries: &[(&str, Option<&str>, Option<u64>)]) -> Result<String, PluginError> {
    let mut inner = String::from("<files>");
    for (url, fname, size) in entries {
        inner.push_str("<file>");
        inner.push_str("<url>");
        inner.push_str(&B64.encode(url.as_bytes()));
        inner.push_str("</url>");
        if let Some(name) = fname {
            inner.push_str("<filename>");
            inner.push_str(&B64.encode(name.as_bytes()));
            inner.push_str("</filename>");
        }
        if let Some(s) = size {
            inner.push_str(&format!("<size>{}</size>", s));
        }
        inner.push_str("</file>");
    }
    inner.push_str("</files>");

    let cipher = aes128_cbc_encrypt(&DLC_KEY, &DLC_IV, inner.as_bytes())?;
    let content_b64 = B64.encode(&cipher);
    let outer = format!(
        "<dlc version=\"1\"><header><app>Vortex</app></header><content>{}</content></dlc>",
        content_b64
    );
    Ok(B64.encode(outer.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(&'static str, Option<&'static str>, Option<u64>)> {
        vec![
            (
                "https://hoster.example/file1.zip",
                Some("file1.zip"),
                Some(1024),
            ),
            ("https://hoster.example/file2.bin", None, None),
        ]
    }

    #[test]
    fn encode_then_decode_recovers_links() {
        let container = encode(&entries()).unwrap();
        let links = decode(container.as_bytes()).unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].url, "https://hoster.example/file1.zip");
        assert_eq!(links[0].filename.as_deref(), Some("file1.zip"));
        assert_eq!(links[0].size_bytes, Some(1024));
        assert_eq!(links[1].url, "https://hoster.example/file2.bin");
        assert!(links[1].filename.is_none());
        assert!(links[1].size_bytes.is_none());
    }

    #[test]
    fn decode_rejects_empty_url() {
        let container = encode(&[("", None, None)]).unwrap();

        let err = decode(container.as_bytes()).unwrap_err();

        assert!(matches!(err, PluginError::MissingField("url")));
    }

    #[test]
    fn looks_like_dlc_accepts_synthetic() {
        let container = encode(&entries()).unwrap();
        assert!(looks_like_dlc(container.as_bytes()));
    }

    #[test]
    fn looks_like_dlc_rejects_plain_xml() {
        assert!(!looks_like_dlc(b"<?xml version=\"1.0\"?><html/>"));
    }

    #[test]
    fn looks_like_dlc_rejects_random_base64() {
        let blob = B64.encode(b"<html><body>not a dlc</body></html>");
        assert!(!looks_like_dlc(blob.as_bytes()));
    }

    #[test]
    fn looks_like_dlc_rejects_short_blob() {
        assert!(!looks_like_dlc(b"abc"));
    }

    #[test]
    fn decode_rejects_invalid_base64_outer() {
        let err = decode(b"!@#$%^&*()_+ not base64").unwrap_err();
        assert!(matches!(err, PluginError::Base64(_)));
    }

    #[test]
    fn decode_rejects_missing_content_tag() {
        let outer = "<dlc><header/></dlc>";
        let blob = B64.encode(outer.as_bytes());
        let err = decode(blob.as_bytes()).unwrap_err();
        assert!(matches!(err, PluginError::MissingField("content")));
    }

    #[test]
    fn decode_rejects_zero_files() {
        let inner = "<files></files>";
        let cipher = aes128_cbc_encrypt(&DLC_KEY, &DLC_IV, inner.as_bytes()).unwrap();
        let outer = format!("<dlc><content>{}</content></dlc>", B64.encode(&cipher));
        let blob = B64.encode(outer.as_bytes());
        let err = decode(blob.as_bytes()).unwrap_err();
        assert!(matches!(err, PluginError::Malformed(_)));
    }

    #[test]
    fn decode_handles_unicode_filename() {
        let entries = vec![("https://example.com/x", Some("éàü 文档.zip"), Some(42))];
        let container = encode(&entries).unwrap();
        let links = decode(container.as_bytes()).unwrap();
        assert_eq!(links[0].filename.as_deref(), Some("éàü 文档.zip"));
    }

    #[test]
    fn decode_omits_empty_filename() {
        let container = encode(&[("https://example.com/x", Some(""), None)]).unwrap();
        let links = decode(container.as_bytes()).unwrap();

        assert_eq!(links[0].filename.as_deref(), None);
    }
}
