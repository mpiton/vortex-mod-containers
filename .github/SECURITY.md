# Security Policy

## Supported Versions

<!-- Update this table as needed -->

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of these methods:

1. **GitHub Security Advisories**: Use the [Security Advisory](https://github.com/mpiton/vortex-mod-containers/security/advisories/new) feature
2. **Email**: Send details to `matpiton@protonmail.com`

### Scope

Security-sensitive areas in this plugin:

- **Crypto** (`src/crypto.rs`): AES-128-CBC primitives. Bugs that allow plaintext recovery without the embedded key, or that cause buffer over-reads on malformed input, are in-scope.
- **Format parsers** (`src/{dlc,ccf,rsdf,metalink}.rs`): Malformed container blobs that trigger panics, infinite loops, or DoS-grade memory growth.
- **Trust boundary**: This plugin declares `http = false`. A change that re-enables outbound network calls without an explicit ADR + `plugin.toml` capability bump is a security regression.

### What to Include

- Type of vulnerability
- Steps to reproduce (a minimal container blob is ideal)
- Impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity

We appreciate responsible disclosure and will credit reporters in the security advisory (unless you prefer to remain anonymous).
