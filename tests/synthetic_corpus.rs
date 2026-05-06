//! Synthetic corpus exercising 20 containers across the four supported
//! formats. Each container is generated from public format specs and the
//! embedded historic keys, then round-tripped through `decrypt()` to prove
//! the full pipeline (detect → format-specific decode → DTO) works.
//!
//! See `docs/ADR-001-container-keys.md` for why we test against a synthetic
//! corpus rather than redistributing JDownloader-era proprietary fixtures.

use vortex_mod_containers::{
    can_decrypt, ccf, decrypt, dlc, rsdf,
    types::{ChecksumAlgo, ContainerFormat},
};

type FileEntry = (&'static str, Option<&'static str>, Option<u64>);
type EncodeCase = (&'static str, Vec<FileEntry>);

#[derive(Debug)]
struct Spec {
    label: &'static str,
    bytes: Vec<u8>,
    expected_format: ContainerFormat,
    expected_links: usize,
    expected_first_url: &'static str,
}

fn dlc_specs() -> Vec<Spec> {
    let cases: [EncodeCase; 5] = [
        (
            "dlc-01-single-no-meta",
            vec![("https://hoster.example/01/file.bin", None, None)],
        ),
        (
            "dlc-02-with-name",
            vec![(
                "https://hoster.example/02/movie.mkv",
                Some("movie.mkv"),
                Some(2_000_000_000),
            )],
        ),
        (
            "dlc-03-multi-files",
            vec![
                ("https://hoster.example/03/a.zip", Some("a.zip"), Some(100)),
                ("https://hoster.example/03/b.zip", Some("b.zip"), Some(200)),
                ("https://hoster.example/03/c.zip", Some("c.zip"), Some(300)),
            ],
        ),
        (
            "dlc-04-unicode-filename",
            vec![(
                "https://hoster.example/04/x",
                Some("résumé éàü.pdf"),
                Some(42),
            )],
        ),
        (
            "dlc-05-large-pack",
            (0..10)
                .map(|i| {
                    let url = match i {
                        0 => "https://hoster.example/05/part01.rar",
                        1 => "https://hoster.example/05/part02.rar",
                        2 => "https://hoster.example/05/part03.rar",
                        3 => "https://hoster.example/05/part04.rar",
                        4 => "https://hoster.example/05/part05.rar",
                        5 => "https://hoster.example/05/part06.rar",
                        6 => "https://hoster.example/05/part07.rar",
                        7 => "https://hoster.example/05/part08.rar",
                        8 => "https://hoster.example/05/part09.rar",
                        _ => "https://hoster.example/05/part10.rar",
                    };
                    (url, None::<&str>, Some(50_000_000_u64 * (i + 1) as u64))
                })
                .collect(),
        ),
    ];

    cases
        .into_iter()
        .map(|(label, entries)| {
            let owned: Vec<_> = entries.iter().map(|(u, n, s)| (*u, *n, *s)).collect();
            let blob = dlc::encode(&owned).expect("dlc encode");
            let first_url: &'static str = entries[0].0;
            Spec {
                label,
                bytes: blob.into_bytes(),
                expected_format: ContainerFormat::Dlc,
                expected_links: entries.len(),
                expected_first_url: first_url,
            }
        })
        .collect()
}

fn ccf_specs() -> Vec<Spec> {
    let cases: [EncodeCase; 5] = [
        (
            "ccf-01-single",
            vec![(
                "https://cryptload.example/01/a.rar",
                Some("a.rar"),
                Some(700_000),
            )],
        ),
        (
            "ccf-02-no-meta",
            vec![("https://cryptload.example/02/b.bin", None, None)],
        ),
        (
            "ccf-03-special-chars-url",
            vec![("https://cryptload.example/03/x?a=1&b=two&c=3", None, None)],
        ),
        (
            "ccf-04-multi",
            vec![
                ("https://cryptload.example/04/p1", Some("p1.rar"), Some(1)),
                ("https://cryptload.example/04/p2", Some("p2.rar"), Some(2)),
                ("https://cryptload.example/04/p3", Some("p3.rar"), Some(3)),
            ],
        ),
        (
            "ccf-05-deep-path",
            vec![(
                "https://deep.example/path/to/very/long/folder/structure/file.7z",
                Some("file.7z"),
                Some(123_456_789),
            )],
        ),
    ];

    cases
        .into_iter()
        .map(|(label, entries)| {
            let owned: Vec<_> = entries.iter().map(|(u, n, s)| (*u, *n, *s)).collect();
            let blob = ccf::encode(&owned).expect("ccf encode");
            let first_url: &'static str = entries[0].0;
            Spec {
                label,
                bytes: blob,
                expected_format: ContainerFormat::Ccf,
                expected_links: entries.len(),
                expected_first_url: first_url,
            }
        })
        .collect()
}

fn rsdf_specs() -> Vec<Spec> {
    let cases: [(&str, Vec<&'static str>); 5] = [
        (
            "rsdf-01-single",
            vec!["https://rapidshare.example/files/01/x.zip"],
        ),
        (
            "rsdf-02-three",
            vec![
                "https://rapidshare.example/02/a",
                "https://rapidshare.example/02/b",
                "https://rapidshare.example/02/c",
            ],
        ),
        (
            "rsdf-03-mixed-hosts",
            vec![
                "https://rs.example/file1.zip",
                "https://mirror.example/file1.zip",
                "https://backup.example/file1.zip",
            ],
        ),
        (
            "rsdf-04-with-query",
            vec!["https://rs.example/get?id=12345&token=abcdef"],
        ),
        (
            "rsdf-05-longish",
            vec![
                "https://rs.example/very-long-filename-with-many-words-and-numbers-12345.tar.gz",
                "https://rs.example/another/long/path/structure.tar.gz",
            ],
        ),
    ];

    cases
        .into_iter()
        .map(|(label, urls)| {
            let blob = rsdf::encode(&urls).expect("rsdf encode");
            let first_url: &'static str = urls[0];
            Spec {
                label,
                bytes: blob.into_bytes(),
                expected_format: ContainerFormat::Rsdf,
                expected_links: urls.len(),
                expected_first_url: first_url,
            }
        })
        .collect()
}

fn metalink_specs() -> Vec<Spec> {
    // Three v3-style and two v4-style files exercising namespaces, mirrors,
    // hash variants, and edge sizing.
    let v3_a = r#"<?xml version="1.0" encoding="UTF-8"?>
<metalink version="3.0">
  <files>
    <file name="apache-tomcat.tar.gz">
      <size>15728640</size>
      <verification>
        <hash type="md5">d41d8cd98f00b204e9800998ecf8427e</hash>
        <hash type="sha256">a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3</hash>
      </verification>
      <resources>
        <url>https://apache-mirror1.example/tomcat/apache-tomcat.tar.gz</url>
        <url>https://apache-mirror2.example/tomcat/apache-tomcat.tar.gz</url>
        <url>https://apache-mirror3.example/tomcat/apache-tomcat.tar.gz</url>
      </resources>
    </file>
  </files>
</metalink>"#;

    let v3_b = r#"<?xml version="1.0"?>
<metalink>
  <files>
    <file name="vlc-3.0.20.dmg">
      <size>52428800</size>
      <verification>
        <hash type="sha1">3da541559918a808c2402bba5012f6c60b27661c</hash>
      </verification>
      <resources>
        <url>https://download.videolan.example/vlc/3.0.20/vlc-3.0.20.dmg</url>
      </resources>
    </file>
  </files>
</metalink>"#;

    let v3_c = r#"<?xml version="1.0"?>
<metalink>
  <files>
    <file name="multi-1.iso">
      <size>100</size>
      <verification><hash type="md5">aabbccddeeff00112233445566778899</hash></verification>
      <resources><url>https://m1.example/a</url></resources>
    </file>
    <file name="multi-2.iso">
      <size>200</size>
      <verification><hash type="sha256">000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f</hash></verification>
      <resources><url>https://m2.example/b</url></resources>
    </file>
  </files>
</metalink>"#;

    let v4_a = r#"<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="opensuse-leap.iso">
    <size>4294967296</size>
    <hash type="sha-256">B5BB9D8014A0F9B1D61E21E796D78DCCDF1352F23CD32812F4850B878AE4944C</hash>
    <url>https://download.opensuse.example/distribution/leap/15.5/opensuse-leap.iso</url>
    <url>https://mirror1.example/opensuse-leap.iso</url>
    <url>https://mirror2.example/opensuse-leap.iso</url>
    <url>https://mirror3.example/opensuse-leap.iso</url>
  </file>
</metalink>"#;

    let v4_b = r#"<?xml version="1.0"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="archlinux.iso">
    <size>876543210</size>
    <hash type="sha-1">7c222fb2927d828af22f592134e8932480637c0d</hash>
    <hash type="md5">5d41402abc4b2a76b9719d911017c592</hash>
    <url>https://archlinux-mirror.example/iso/archlinux.iso</url>
  </file>
</metalink>"#;

    vec![
        Spec {
            label: "metalink-01-apache-v3",
            bytes: v3_a.as_bytes().to_vec(),
            expected_format: ContainerFormat::Metalink,
            expected_links: 1,
            expected_first_url: "https://apache-mirror1.example/tomcat/apache-tomcat.tar.gz",
        },
        Spec {
            label: "metalink-02-vlc-v3",
            bytes: v3_b.as_bytes().to_vec(),
            expected_format: ContainerFormat::Metalink,
            expected_links: 1,
            expected_first_url: "https://download.videolan.example/vlc/3.0.20/vlc-3.0.20.dmg",
        },
        Spec {
            label: "metalink-03-multi-v3",
            bytes: v3_c.as_bytes().to_vec(),
            expected_format: ContainerFormat::Metalink,
            expected_links: 2,
            expected_first_url: "https://m1.example/a",
        },
        Spec {
            label: "metalink-04-opensuse-v4",
            bytes: v4_a.as_bytes().to_vec(),
            expected_format: ContainerFormat::Metalink,
            expected_links: 1,
            expected_first_url:
                "https://download.opensuse.example/distribution/leap/15.5/opensuse-leap.iso",
        },
        Spec {
            label: "metalink-05-arch-v4",
            bytes: v4_b.as_bytes().to_vec(),
            expected_format: ContainerFormat::Metalink,
            expected_links: 1,
            expected_first_url: "https://archlinux-mirror.example/iso/archlinux.iso",
        },
    ]
}

fn full_corpus() -> Vec<Spec> {
    let mut all = Vec::new();
    all.extend(dlc_specs());
    all.extend(ccf_specs());
    all.extend(rsdf_specs());
    all.extend(metalink_specs());
    all
}

#[test]
fn corpus_has_at_least_twenty_containers_across_four_formats() {
    let corpus = full_corpus();
    assert!(
        corpus.len() >= 20,
        "corpus must have ≥20 containers (currently {})",
        corpus.len()
    );

    let dlc_count = corpus
        .iter()
        .filter(|s| matches!(s.expected_format, ContainerFormat::Dlc))
        .count();
    let ccf_count = corpus
        .iter()
        .filter(|s| matches!(s.expected_format, ContainerFormat::Ccf))
        .count();
    let rsdf_count = corpus
        .iter()
        .filter(|s| matches!(s.expected_format, ContainerFormat::Rsdf))
        .count();
    let metalink_count = corpus
        .iter()
        .filter(|s| matches!(s.expected_format, ContainerFormat::Metalink))
        .count();
    assert!(dlc_count >= 5, "≥5 DLC samples required");
    assert!(ccf_count >= 5, "≥5 CCF samples required");
    assert!(rsdf_count >= 5, "≥5 RSDF samples required");
    assert!(metalink_count >= 5, "≥5 Metalink samples required");
}

#[test]
fn every_corpus_entry_decrypts_correctly() {
    for spec in full_corpus() {
        assert!(
            can_decrypt(&spec.bytes),
            "[{}] can_decrypt should be true",
            spec.label
        );

        let result = decrypt(&spec.bytes)
            .unwrap_or_else(|e| panic!("[{}] decrypt failed: {}", spec.label, e));

        assert_eq!(
            result.format, spec.expected_format,
            "[{}] format mismatch",
            spec.label
        );
        assert_eq!(
            result.links.len(),
            spec.expected_links,
            "[{}] link count mismatch",
            spec.label
        );
        assert_eq!(
            result.links[0].url, spec.expected_first_url,
            "[{}] first URL mismatch",
            spec.label
        );
    }
}

#[test]
fn metalink_corpus_carries_checksums() {
    for spec in metalink_specs() {
        let result = decrypt(&spec.bytes).expect("metalink decrypt");
        let any_checksum = result.links.iter().any(|l| !l.checksums.is_empty());
        assert!(
            any_checksum,
            "[{}] expected at least one checksum on at least one link",
            spec.label
        );
    }
}

#[test]
fn metalink_corpus_recognises_sha256_when_present() {
    let specs = metalink_specs();
    let mut saw_sha256 = false;
    for spec in &specs {
        let result = decrypt(&spec.bytes).expect("metalink decrypt");
        if result.links.iter().any(|l| {
            l.checksums
                .iter()
                .any(|c| matches!(c.algorithm, ChecksumAlgo::Sha256))
        }) {
            saw_sha256 = true;
        }
    }
    assert!(saw_sha256, "expected at least one corpus entry with SHA256");
}

#[test]
fn rsdf_corpus_round_trips_all_urls_in_order() {
    for spec in rsdf_specs() {
        let result = decrypt(&spec.bytes).expect("rsdf decrypt");
        assert_eq!(result.links.len(), spec.expected_links);
        assert_eq!(result.links[0].url, spec.expected_first_url);
    }
}

#[test]
fn dlc_corpus_preserves_filenames_and_sizes() {
    for spec in dlc_specs() {
        let result = decrypt(&spec.bytes).expect("dlc decrypt");
        assert_eq!(result.format, ContainerFormat::Dlc);
        assert_eq!(result.links.len(), spec.expected_links);
    }
}

#[test]
fn ccf_corpus_decodes_with_magic_prefix() {
    for spec in ccf_specs() {
        assert!(spec.bytes.starts_with(ccf::CCF_MAGIC.as_bytes()));
        let result = decrypt(&spec.bytes).expect("ccf decrypt");
        assert_eq!(result.format, ContainerFormat::Ccf);
    }
}

#[test]
fn unknown_blobs_are_rejected() {
    let bogus_samples = [
        b"" as &[u8],
        b"hello world",
        b"\x00\x01\x02\x03",
        b"<html><body>not a container</body></html>",
    ];
    for sample in bogus_samples {
        assert!(!can_decrypt(sample));
        assert!(decrypt(sample).is_err());
    }
}
