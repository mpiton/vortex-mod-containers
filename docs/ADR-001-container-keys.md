# ADR-001 — Container key strategy

- **Status:** Accepted
- **Date:** 2026-05-06
- **Context window:** Vortex sprint task #41 (`vortex-mod-containers` v1.0)

## Context

Decrypting JDownloader-era link containers (DLC, CCF, RSDF) requires a
symmetric AES key/IV pair per format. Three options were on the table:

1. **Embed the historic public keys.** The keys used by JDownloader v1 / DLC
   v1, Cryptload v1, and RapidShare RSDF have been public for over a decade
   (community-documented in dcrypt-it, jd-decrypter, and similar open-source
   projects). They are not secrets — the encryption is obfuscation, not
   security.
2. **Fetch a per-container key from `service.jdownloader.org/dlcrypt.php`.**
   This is what the official JDownloader does for DLC v3 containers.
3. **Refuse to decrypt unknown containers and surface a UX prompt.** Pure
   no-op fallback.

## Decision

We pick option **(1)** as the v1 default. The plugin embeds:

| Format | Key / IV                                              | Source                                |
|--------|-------------------------------------------------------|---------------------------------------|
| DLC    | KEY = `cb99b5cbc24db398` IV = `9bc24cb995cb98b3` (ASCII) | JDownloader v1 historic, public       |
| RSDF   | KEY = `8C 35 19 2D 96 4D C3 18 2C 6F 84 F3 25 22 39 EB`, IV = KEY | RapidShare legacy, public             |
| CCF    | KEY = `v0rt3xCryptL0adC` IV = `CcfVortexInitVec` (ASCII) | Vortex-specific (see "v1 scope" below) |

We **explicitly do not** implement option (2): no outbound HTTP to
`service.jdownloader.org`. Reasons:

- **Privacy.** Calling the JD service leaks the user's container hash to a
  third party. Vortex's value proposition is local, sovereign download
  management — keeping the trust surface zero is a feature.
- **Reproducibility.** A WASM plugin with no `http` capability declaration
  is fully sandboxed. Adding the JD service would require granting the
  `http_request` host function.
- **Reliability.** The JD service has been intermittently unavailable
  historically; relying on it would couple the plugin's success rate to a
  third-party endpoint we do not control.

Option (3) is the **fallback** for any container variant we cannot decrypt
with the embedded key — `decrypt()` returns `PluginError::Decrypt(...)` and
the host shows a "Unsupported container variant" message. The user can
then re-run the file through the original JDownloader to extract URLs
manually.

## Consequences

- **DLC v3** containers fail to decrypt because they require a per-file key
  fetched from `service.jdownloader.org`. We document this explicitly and
  do not silently retry.
- **CCF** uses a Vortex-specific key in v1 because the actual Cryptload key
  varies by version (v1 / v2 / v3) and a complete reverse-engineering pass
  was out of scope for the initial release. v1.1 will add real-world
  Cryptload keys after we capture and analyse a corpus.
- **RSDF** and **DLC v1** are fully interoperable with containers produced
  by JDownloader v1 or open-source dcrypt-it utilities.

## Test corpus

The `tests/synthetic_corpus.rs` integration suite generates 20 synthetic
containers (5 per format) using the embedded keys and the `encode` helpers
in each format module. Round-tripping them through `decrypt()` proves the
end-to-end pipeline (detect → format-specific decode → DTO) works.

We chose synthetic fixtures over redistributing JDownloader-era proprietary
container files because:

- The historical files reference long-dead hosters (RapidShare, Cryptload's
  own short-link service) and would test stale URLs rather than parser
  correctness.
- Many real-world fixtures point to copyrighted material; redistributing
  them — even encrypted — is legally murky.
- Synthetic corpora let us deterministically cover edge cases (Unicode
  filenames, large packs, multi-mirror Metalink) that historical samples
  often lack.

If a future release wants to validate against real JD captures, drop them
into `tests/fixtures/real-world/` and add a guarded test behind an
environment variable so CI does not redistribute the binaries.

## Roadmap

- v1.1 — Cryptload v1/v2 key reverse-engineering pass.
- v1.2 — Optional `http=true` capability with **explicit user consent** to
  decrypt DLC v3 via the JD service.
- v1.3 — Metalink XML signature verification (PGP, RFC 5854 §6).
