//! Metalink decoder — supports v3 (`.metalink`) and v4/RFC 5854 (`.meta4`).
//!
//! Metalink is a plain XML format: no encryption, just structural parsing to
//! recover URLs, mirrors, file sizes and checksums. The parser is SAX-style on
//! top of `quick-xml` so it tolerates both v3 elements (`<resources><url>`)
//! and v4 elements (`<url>` directly under `<file>`), as well as either case
//! of the hash type attribute (`sha-256`, `SHA256`, etc.).

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::error::PluginError;
use crate::types::{Checksum, ChecksumAlgo, ContainerLink};
use crate::xml::{decode_reference, decode_text};

const MAGIC_HINTS: &[&str] = &["<metalink", "<Metalink", "<METALINK"];
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_XML_DEPTH: usize = 64;
const MAX_XML_ELEMENTS: usize = 50_000;
const MAX_ATTRIBUTES_PER_ELEMENT: usize = 64;
const MAX_TEXT_BYTES: usize = 64 * 1024;

pub fn looks_like_metalink(bytes: &[u8]) -> bool {
    let head_len = bytes.len().min(4096);
    let head = &bytes[..head_len];
    let head_str = match std::str::from_utf8(head) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let trimmed = head_str.trim_start();
    if !trimmed.starts_with("<?xml")
        && !trimmed.starts_with("<metalink")
        && !MAGIC_HINTS.iter().any(|m| trimmed.contains(m))
    {
        return false;
    }
    MAGIC_HINTS.iter().any(|m| head_str.contains(m))
}

pub fn decode(bytes: &[u8]) -> Result<Vec<ContainerLink>, PluginError> {
    ensure_within_limit(bytes.len(), MAX_INPUT_BYTES, "input bytes")?;
    let xml = std::str::from_utf8(bytes)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut state = ParseState::default();
    let mut buf = Vec::new();
    let mut depth = 0;
    let mut elements = 0;
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(e) => {
                count_element(&mut elements)?;
                depth += 1;
                ensure_within_limit(depth, MAX_XML_DEPTH, "XML depth")?;
                validate_attributes(&e)?;
                state.on_start(e)?;
            }
            Event::Empty(e) => {
                count_element(&mut elements)?;
                ensure_within_limit(depth + 1, MAX_XML_DEPTH, "XML depth")?;
                validate_attributes(&e)?;
                state.on_start(e.clone())?;
                state.on_end(e.name().as_ref())?;
            }
            Event::Text(t) => {
                state.append_text(&decode_text(&t)?)?;
            }
            Event::CData(c) => {
                state.append_text(&c.decode()?)?;
            }
            Event::GeneralRef(reference) => {
                state.append_text(&decode_reference(&reference)?)?;
            }
            Event::End(e) => {
                state.on_end(e.name().as_ref())?;
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        buf.clear();
    }
    if state.files.is_empty() {
        return Err(PluginError::Malformed("no <file> entries".into()));
    }
    Ok(state.files)
}

fn ensure_within_limit(
    value: usize,
    limit: usize,
    resource: &'static str,
) -> Result<(), PluginError> {
    if value > limit {
        return Err(PluginError::LimitExceeded { resource, limit });
    }
    Ok(())
}

fn count_element(elements: &mut usize) -> Result<(), PluginError> {
    *elements += 1;
    ensure_within_limit(*elements, MAX_XML_ELEMENTS, "XML elements")
}

fn validate_attributes(element: &BytesStart<'_>) -> Result<(), PluginError> {
    for (index, attribute) in element.attributes().enumerate() {
        if index >= MAX_ATTRIBUTES_PER_ELEMENT {
            return Err(PluginError::LimitExceeded {
                resource: "attributes per element",
                limit: MAX_ATTRIBUTES_PER_ELEMENT,
            });
        }
        attribute?;
    }
    Ok(())
}

#[derive(Default)]
struct ParseState {
    in_file: bool,
    current_file: Option<FileBuilder>,
    text_target: Option<TextTarget>,
    text_buffer: String,
    current_hash_algo: Option<ChecksumAlgo>,
    files: Vec<ContainerLink>,
}

#[derive(Clone, Copy)]
enum TextTarget {
    Size,
    Url,
    Hash,
}

#[derive(Default)]
struct FileBuilder {
    name: Option<String>,
    size: Option<u64>,
    urls: Vec<String>,
    hashes: Vec<Checksum>,
}

impl ParseState {
    fn on_start(&mut self, e: BytesStart<'_>) -> Result<(), PluginError> {
        let local = local_name(e.name().as_ref());
        match local.as_str() {
            "file" => {
                self.in_file = true;
                let mut builder = FileBuilder::default();
                for attr in e.attributes() {
                    let attr = attr?;
                    if local_name(attr.key.as_ref()) == "name" {
                        builder.name =
                            Some(attr.normalized_value(XmlVersion::Implicit1_0)?.into_owned());
                    }
                }
                self.current_file = Some(builder);
            }
            "size" if self.in_file => self.start_text(TextTarget::Size),
            "url" if self.in_file => self.start_text(TextTarget::Url),
            "hash" if self.in_file => {
                self.current_hash_algo = parse_hash_attr(&e)?;
                self.start_text(TextTarget::Hash);
            }
            _ => {}
        }
        Ok(())
    }

    fn start_text(&mut self, target: TextTarget) {
        self.text_target = Some(target);
        self.text_buffer.clear();
    }

    fn append_text(&mut self, text: &str) -> Result<(), PluginError> {
        if self.text_target.is_some() {
            ensure_within_limit(
                self.text_buffer.len().saturating_add(text.len()),
                MAX_TEXT_BYTES,
                "text bytes",
            )?;
            self.text_buffer.push_str(text);
        }
        Ok(())
    }

    fn finish_text(&mut self) {
        let Some(target) = self.text_target else {
            return;
        };
        let Some(builder) = self.current_file.as_mut() else {
            return;
        };
        let trimmed = self.text_buffer.trim();
        if trimmed.is_empty() {
            return;
        }
        match target {
            TextTarget::Size => {
                if let Ok(n) = trimmed.parse::<u64>() {
                    builder.size = Some(n);
                }
            }
            TextTarget::Url => builder.urls.push(trimmed.to_string()),
            TextTarget::Hash => {
                if let Some(algo) = self.current_hash_algo {
                    builder.hashes.push(Checksum {
                        algorithm: algo,
                        value: trimmed.to_lowercase(),
                    });
                }
            }
        }
    }

    fn on_end(&mut self, name: &[u8]) -> Result<(), PluginError> {
        let local = local_name(name);
        match local.as_str() {
            "file" => {
                self.in_file = false;
                if let Some(b) = self.current_file.take() {
                    let link = into_link(b)?;
                    self.files.push(link);
                }
            }
            "size" | "url" | "hash" => {
                self.finish_text();
                self.text_target = None;
                self.text_buffer.clear();
                if local == "hash" {
                    self.current_hash_algo = None;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn into_link(b: FileBuilder) -> Result<ContainerLink, PluginError> {
    let mut urls = b.urls.into_iter();
    let primary = urls
        .next()
        .ok_or(PluginError::Malformed("file has no <url>".into()))?;
    Ok(ContainerLink {
        url: primary,
        filename: b.name,
        size_bytes: b.size,
        mirrors: urls.collect(),
        checksums: b.hashes,
    })
}

fn parse_hash_attr(e: &BytesStart<'_>) -> Result<Option<ChecksumAlgo>, PluginError> {
    for attr in e.attributes() {
        let attr = attr?;
        if local_name(attr.key.as_ref()) == "type" {
            let raw = attr
                .normalized_value(XmlVersion::Implicit1_0)?
                .into_owned()
                .to_lowercase();
            let normalised = raw.replace('-', "");
            return Ok(match normalised.as_str() {
                "md5" => Some(ChecksumAlgo::Md5),
                "sha1" => Some(ChecksumAlgo::Sha1),
                "sha256" => Some(ChecksumAlgo::Sha256),
                _ => None,
            });
        }
    }
    Ok(None)
}

fn local_name(name: &[u8]) -> String {
    let s = String::from_utf8_lossy(name);
    s.rsplit_once(':')
        .map(|(_, local)| local.to_string())
        .unwrap_or_else(|| s.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V3_SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<metalink version="3.0">
  <files>
    <file name="example.zip">
      <size>12345</size>
      <verification>
        <hash type="sha256">deadbeefcafe</hash>
        <hash type="md5">abcd1234</hash>
      </verification>
      <resources>
        <url>https://primary.example/example.zip</url>
        <url>https://mirror1.example/example.zip</url>
      </resources>
    </file>
  </files>
</metalink>"#;

    const V4_SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="vlc.iso">
    <size>1048576</size>
    <hash type="sha-256">FEEDFACE</hash>
    <url>https://download.example/vlc.iso</url>
    <url>https://eu.example/vlc.iso</url>
    <url>https://us.example/vlc.iso</url>
  </file>
</metalink>"#;

    #[test]
    fn looks_like_metalink_accepts_v3() {
        assert!(looks_like_metalink(V3_SAMPLE.as_bytes()));
    }

    #[test]
    fn looks_like_metalink_accepts_v4() {
        assert!(looks_like_metalink(V4_SAMPLE.as_bytes()));
    }

    #[test]
    fn looks_like_metalink_rejects_random() {
        assert!(!looks_like_metalink(
            b"<html><body>not metalink</body></html>"
        ));
        assert!(!looks_like_metalink(b"\x00\x01\x02 binary"));
    }

    #[test]
    fn decode_v3_extracts_primary_and_mirrors() {
        let links = decode(V3_SAMPLE.as_bytes()).unwrap();
        assert_eq!(links.len(), 1);
        let f = &links[0];
        assert_eq!(f.url, "https://primary.example/example.zip");
        assert_eq!(f.mirrors, vec!["https://mirror1.example/example.zip"]);
        assert_eq!(f.filename.as_deref(), Some("example.zip"));
        assert_eq!(f.size_bytes, Some(12345));
        assert_eq!(f.checksums.len(), 2);
        assert!(f
            .checksums
            .iter()
            .any(|c| matches!(c.algorithm, ChecksumAlgo::Sha256) && c.value == "deadbeefcafe"));
        assert!(f
            .checksums
            .iter()
            .any(|c| matches!(c.algorithm, ChecksumAlgo::Md5) && c.value == "abcd1234"));
    }

    #[test]
    fn decode_v4_handles_namespace_and_dashed_hash() {
        let links = decode(V4_SAMPLE.as_bytes()).unwrap();
        assert_eq!(links.len(), 1);
        let f = &links[0];
        assert_eq!(f.url, "https://download.example/vlc.iso");
        assert_eq!(f.mirrors.len(), 2);
        assert_eq!(f.size_bytes, Some(1_048_576));
        assert_eq!(f.checksums.len(), 1);
        assert!(matches!(f.checksums[0].algorithm, ChecksumAlgo::Sha256));
        assert_eq!(f.checksums[0].value, "feedface");
    }

    #[test]
    fn decode_rejects_file_without_url() {
        let xml = r#"<metalink><file name="empty"><size>0</size></file></metalink>"#;
        let err = decode(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, PluginError::Malformed(_)));
    }

    #[test]
    fn decode_rejects_when_no_files() {
        let xml = r#"<metalink></metalink>"#;
        let err = decode(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, PluginError::Malformed(_)));
    }

    #[test]
    fn decode_handles_multiple_files() {
        let xml = r#"<metalink>
            <file name="a.bin"><size>1</size><url>https://a.example/a.bin</url></file>
            <file name="b.bin"><size>2</size><url>https://b.example/b.bin</url></file>
        </metalink>"#;
        let links = decode(xml.as_bytes()).unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].filename.as_deref(), Some("a.bin"));
        assert_eq!(links[1].filename.as_deref(), Some("b.bin"));
    }

    #[test]
    fn decode_rejects_input_larger_than_one_mebibyte() {
        let input = vec![b' '; 1024 * 1024 + 1];

        let err = decode(&input).unwrap_err();

        assert!(matches!(
            err,
            PluginError::LimitExceeded {
                resource: "input bytes",
                limit: 1_048_576
            }
        ));
    }

    #[test]
    fn decode_rejects_excessive_element_depth() {
        let mut xml = String::from("<metalink>");
        for _ in 0..64 {
            xml.push_str("<nested>");
        }
        xml.push_str("<file><url>https://example.com/file.bin</url></file>");
        for _ in 0..64 {
            xml.push_str("</nested>");
        }
        xml.push_str("</metalink>");

        let err = decode(xml.as_bytes()).unwrap_err();

        assert!(matches!(
            err,
            PluginError::LimitExceeded {
                resource: "XML depth",
                limit: 64
            }
        ));
    }

    #[test]
    fn decode_rejects_excessive_element_count() {
        let mut xml = String::from("<metalink>");
        for _ in 0..50_000 {
            xml.push_str("<x/>");
        }
        xml.push_str("<file><url>https://example.com/file.bin</url></file></metalink>");

        let err = decode(xml.as_bytes()).unwrap_err();

        assert!(matches!(
            err,
            PluginError::LimitExceeded {
                resource: "XML elements",
                limit: 50_000
            }
        ));
    }

    #[test]
    fn decode_rejects_excessive_attributes() {
        let mut xml = String::from("<metalink");
        for index in 0..65 {
            xml.push_str(&format!(" a{index}=\"x\""));
        }
        xml.push_str("><file><url>https://example.com/file.bin</url></file></metalink>");

        let err = decode(xml.as_bytes()).unwrap_err();

        assert!(matches!(
            err,
            PluginError::LimitExceeded {
                resource: "attributes per element",
                limit: 64
            }
        ));
    }

    #[test]
    fn decode_rejects_oversized_text_nodes() {
        let url = "a".repeat(64 * 1024 + 1);
        let xml = format!("<metalink><file><url>{url}</url></file></metalink>");

        let err = decode(xml.as_bytes()).unwrap_err();

        assert!(matches!(
            err,
            PluginError::LimitExceeded {
                resource: "text bytes",
                limit: 65_536
            }
        ));
    }

    #[test]
    fn decode_rejects_oversized_text_split_across_references() {
        let references = "&amp;".repeat(MAX_TEXT_BYTES + 1);
        let xml = format!("<metalink><file><url>{references}</url></file></metalink>");

        let err = decode(xml.as_bytes()).unwrap_err();

        assert!(matches!(
            err,
            PluginError::LimitExceeded {
                resource: "text bytes",
                limit: 65_536
            }
        ));
    }

    #[test]
    fn decode_reports_malformed_xml_as_typed_error() {
        let err = decode(b"<metalink><file></metalink>").unwrap_err();

        assert!(matches!(err, PluginError::Xml(_)));
    }
}
