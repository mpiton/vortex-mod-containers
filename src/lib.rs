//! Vortex Containers WASM plugin.
//!
//! Decrypts JDownloader-era link containers (DLC, CCF, RSDF) and parses the
//! Metalink standard (RFC 5854) to feed URLs back into the Link Grabber.
//! The plugin owns no networking — it only transforms bytes → list of
//! `ContainerLink`. The host invokes `decrypt(bytes)` after the user drops
//! a `.dlc` / `.ccf` / `.rsdf` / `.metalink` / `.meta4` file in the UI.
//!
//! ## Exported plugin functions (see `plugin_api.rs` for the WASM bindings)
//!
//! - `can_decrypt(bytes) -> bool`        — magic-byte / structural detection
//! - `detect(bytes) -> DetectResponse`   — explicit format report
//! - `decrypt(bytes) -> DecryptResponse` — full decode, returns links
//!
//! ## Crypto and key strategy
//!
//! Each format embeds a fixed AES-128-CBC key/IV pair. The values come from
//! the historic JDownloader / RapidShare / Cryptload conventions and are
//! considered public; the rationale is captured in
//! `docs/ADR-001-container-keys.md`. The plugin never reaches out to
//! `service.jdownloader.org` — modern DLC v3 containers therefore fall back
//! to an `unsupported variant` error so the host can prompt the user.

pub mod ccf;
pub mod crypto;
pub mod dispatch;
pub mod dlc;
pub mod error;
pub mod metalink;
pub mod rsdf;
pub mod types;
mod xml;

#[cfg(target_family = "wasm")]
mod plugin_api;

use crate::error::PluginError;
use crate::types::{ContainerFormat, DecryptResponse, DetectResponse};

pub fn can_decrypt(bytes: &[u8]) -> bool {
    dispatch::detect(bytes).is_some()
}

pub fn detect(bytes: &[u8]) -> DetectResponse {
    DetectResponse {
        format: dispatch::detect(bytes),
    }
}

pub fn decrypt(bytes: &[u8]) -> Result<DecryptResponse, PluginError> {
    let format = dispatch::detect(bytes).ok_or(PluginError::UnsupportedFormat)?;
    let links = match format {
        ContainerFormat::Ccf => ccf::decode(bytes)?,
        ContainerFormat::Metalink => metalink::decode(bytes)?,
        ContainerFormat::Dlc => dlc::decode(bytes)?,
        ContainerFormat::Rsdf => rsdf::decode(bytes)?,
    };
    Ok(DecryptResponse { format, links })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_decrypt_recognises_metalink() {
        let xml = br#"<metalink><file name="a"><url>https://x</url></file></metalink>"#;
        assert!(can_decrypt(xml));
    }

    #[test]
    fn can_decrypt_returns_false_for_garbage() {
        assert!(!can_decrypt(b"random bytes"));
    }

    #[test]
    fn detect_reports_format() {
        let blob = rsdf::encode(&["https://example.com/x"]).unwrap();
        assert_eq!(detect(blob.as_bytes()).format, Some(ContainerFormat::Rsdf));
    }

    #[test]
    fn detect_reports_none_for_unknown() {
        assert!(detect(b"random").format.is_none());
    }

    #[test]
    fn decrypt_metalink_returns_links() {
        let xml = br#"<metalink><file name="a.bin"><size>10</size><url>https://primary/x</url><url>https://mirror/x</url></file></metalink>"#;
        let r = decrypt(xml).unwrap();
        assert_eq!(r.format, ContainerFormat::Metalink);
        assert_eq!(r.links.len(), 1);
        assert_eq!(r.links[0].url, "https://primary/x");
        assert_eq!(r.links[0].mirrors, vec!["https://mirror/x"]);
    }

    #[test]
    fn decrypt_rsdf_returns_links() {
        let blob = rsdf::encode(&["https://rs.example/a"]).unwrap();
        let r = decrypt(blob.as_bytes()).unwrap();
        assert_eq!(r.format, ContainerFormat::Rsdf);
        assert_eq!(r.links.len(), 1);
    }

    #[test]
    fn decrypt_dlc_returns_links() {
        let blob = dlc::encode(&[(
            "https://hoster.example/file.bin",
            Some("file.bin"),
            Some(99),
        )])
        .unwrap();
        let r = decrypt(blob.as_bytes()).unwrap();
        assert_eq!(r.format, ContainerFormat::Dlc);
        assert_eq!(r.links[0].url, "https://hoster.example/file.bin");
    }

    #[test]
    fn decrypt_ccf_returns_links() {
        let blob = ccf::encode(&[("https://cl.example/file.rar", None, None)]).unwrap();
        let r = decrypt(&blob).unwrap();
        assert_eq!(r.format, ContainerFormat::Ccf);
    }

    #[test]
    fn decrypt_returns_unsupported_for_garbage() {
        let err = decrypt(b"random data not a container").unwrap_err();
        assert!(matches!(err, PluginError::UnsupportedFormat));
    }
}
