# Contributing to vortex-mod-containers

First off, thanks for considering contributing! Every contribution matters, whether it's a bug report, a feature request, or a pull request.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/mpiton/vortex-mod-containers/issues)
2. If not, create a new issue using the **Bug Report** template
3. Include steps to reproduce, expected behavior, and actual behavior

### Suggesting Features

1. Check existing [Feature Requests](https://github.com/mpiton/vortex-mod-containers/issues?q=label%3Aenhancement)
2. Open a new issue using the **Feature Request** template
3. Describe the problem and your proposed solution

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Make your changes following the project's coding standards
4. Write or update tests as needed
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/) format
6. Push to your fork and open a Pull Request

### Commit Message Format

```
<type>(<scope>): <description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`

### Development Setup

```bash
# Clone the repo
git clone https://github.com/mpiton/vortex-mod-containers.git
cd vortex-mod-containers

# Install the WASM target (one-time)
rustup target add wasm32-wasip1

# Run native tests (fast, ~1s)
cargo test

# Lint + format
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Build the WASM artefact
cargo build --target wasm32-wasip1 --release
# Output: target/wasm32-wasip1/release/vortex_mod_containers.wasm
sha256sum target/wasm32-wasip1/release/vortex_mod_containers.wasm
```

### Adding a new container format

1. Add the format module in `src/<format>.rs` with `looks_like_*`, `decode`, and (for testing) `encode` helpers.
2. Wire it through `src/dispatch.rs::detect` and `src/lib.rs::decrypt`.
3. Add 5+ unit tests in the module covering: round-trip, magic detection, malformed input, empty input.
4. Add 5 fixtures in `tests/synthetic_corpus.rs` so the integration suite stays at ≥20 containers.
5. Update `docs/ADR-001-container-keys.md` if the format introduces new key material or trust assumptions.

### Coding standards

- No `.unwrap()` outside tests — return `Result<_, PluginError>` and propagate via `?`.
- No `unsafe` without an ADR justifying it.
- No `#[allow(dead_code)]` or `#[allow(unused)]` — remove the dead code instead.
- The plugin must not gain new capabilities (`http`, `subprocess`, `get_credential`) without an ADR documenting the trust trade-off.
- WASM artefact must stay under 500 KB.

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## Questions?

Open a [Discussion](https://github.com/mpiton/vortex-mod-containers/discussions) or file an issue using the **Question** template.
