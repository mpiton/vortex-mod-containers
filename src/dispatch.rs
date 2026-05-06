//! Format detection and routing.
//!
//! `detect` returns the first matching format based on magic bytes /
//! structural hints. Order matters: CCF and Metalink have unambiguous markers
//! and are checked first; DLC and RSDF rely on text shape and so come last.

use crate::ccf;
use crate::dlc;
use crate::metalink;
use crate::rsdf;
use crate::types::ContainerFormat;

pub fn detect(bytes: &[u8]) -> Option<ContainerFormat> {
    if ccf::looks_like_ccf(bytes) {
        return Some(ContainerFormat::Ccf);
    }
    if metalink::looks_like_metalink(bytes) {
        return Some(ContainerFormat::Metalink);
    }
    if dlc::looks_like_dlc(bytes) {
        return Some(ContainerFormat::Dlc);
    }
    if rsdf::looks_like_rsdf(bytes) {
        return Some(ContainerFormat::Rsdf);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_metalink() {
        let xml = br#"<?xml version="1.0"?><metalink><file name="a"><url>https://x</url></file></metalink>"#;
        assert_eq!(detect(xml), Some(ContainerFormat::Metalink));
    }

    #[test]
    fn detect_rsdf() {
        let blob = rsdf::encode(&["https://example.com/x"]).unwrap();
        assert_eq!(detect(blob.as_bytes()), Some(ContainerFormat::Rsdf));
    }

    #[test]
    fn detect_dlc() {
        let blob = dlc::encode(&[("https://example.com/x", None, None)]).unwrap();
        assert_eq!(detect(blob.as_bytes()), Some(ContainerFormat::Dlc));
    }

    #[test]
    fn detect_ccf() {
        let blob = ccf::encode(&[("https://example.com/x", None, None)]).unwrap();
        assert_eq!(detect(&blob), Some(ContainerFormat::Ccf));
    }

    #[test]
    fn detect_returns_none_for_unknown() {
        assert!(detect(b"random garbage").is_none());
        assert!(detect(b"").is_none());
        assert!(detect(b"<html>not a container</html>").is_none());
    }

    #[test]
    fn ccf_takes_priority_over_metalink_text() {
        // Edge case: nothing should ever look like both, but priority order
        // is part of the public contract.
        let ccf_blob = ccf::encode(&[("https://x.example/y", None, None)]).unwrap();
        assert_eq!(detect(&ccf_blob), Some(ContainerFormat::Ccf));
    }
}
