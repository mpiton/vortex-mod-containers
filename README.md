# vortex-mod-containers

WASM plugin for [Vortex](https://github.com/vortex-app/vortex) — decrypts the
JDownloader-era link containers and parses the Metalink standard.

## Supported formats

| Format    | Extension(s)         | Spec / source                                            | Status |
|-----------|----------------------|----------------------------------------------------------|--------|
| DLC       | `.dlc`               | JDownloader v1, AES-128-CBC, embedded historic key       | ✅      |
| CCF       | `.ccf`               | Cryptload v1, AES-128-CBC, magic `CCF1\n`                | ✅      |
| RSDF      | `.rsdf`              | RapidShare legacy, AES-128-CBC, hex line per URL         | ✅      |
| Metalink  | `.metalink`, `.meta4`| RFC 5854 (v4) + community v3                              | ✅      |

See `docs/ADR-001-container-keys.md` for the rationale behind embedded keys
and the explicit choice to **not** call out to `service.jdownloader.org`.

## Plugin contract

The host invokes three exports after the user drops a file in the Link
Grabber:

| Export        | Input  | Output                                                   |
|---------------|--------|----------------------------------------------------------|
| `can_decrypt` | bytes  | `"true"` / `"false"`                                     |
| `detect`      | bytes  | JSON `{ "format": "dlc" \| "ccf" \| "rsdf" \| "metalink" \| null }` |
| `decrypt`     | bytes  | JSON `{ "format", "links": [{url, filename?, sizeBytes?, mirrors[], checksums[]}] }` |

The plugin owns no networking — it transforms bytes into a structured link
list. The host then routes each `ContainerLink` through the regular hoster
pipeline.

## Metalink limits

Metalink is treated as untrusted XML. Parsing rejects inputs above 1 MiB,
nesting deeper than 64 elements, more than 50,000 elements, more than 64
attributes on one element, or parsed field text above 64 KiB. Limit violations
and malformed XML return typed plugin errors without partial output.

## Build

```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release

# Output:
#   target/wasm32-wasip1/release/vortex_mod_containers.wasm
sha256sum target/wasm32-wasip1/release/vortex_mod_containers.wasm
```

## Test

```bash
cargo test            # native — 60+ unit + integration tests
cargo clippy --all-targets -- -D warnings
```

The integration suite (`tests/synthetic_corpus.rs`) generates a
20-container fixture covering all four formats and round-trips them through
the public `decrypt()` API.

## License

GPL-3.0 — see `LICENSE`.
