# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the API (paths, parameters, stored data and token
claims) may change in a minor release. Such changes are listed under **Changed**
or **Removed**, and changes to the storage format are called out explicitly.

## [Unreleased]

## [0.1.0] - 2026-11-01

First public release.

### Added

- Courier secrets engine for Vault: delivers a credential to an allowlisted
  receipt URL without the requester ever seeing it.
- Unauthenticated `request/<role>` endpoint that answers `204` and delivers in the
  background, with optional nonce, retry and per-role receipt URL allowlist.
- `jwt` credential type: signs JSON Web Tokens for arbitrary service identities
  and publishes the OIDC discovery document and JWKS. The credential type is
  chosen per mount with the mount option `type`.
- Signing key generation and rotation (`keys/rotate`), with keys stored behind
  the seal.
- Mount configuration (`config`) with network policy, rate limits and delivery
  parameters, and role management (`roles/<name>`).
- Plugin version reporting to Vault, set at build time from the git tag.
- Unit tests, fuzz and benchmark tests, and a live test that runs the plugin in a
  real Vault (`make live-test`), verified on Vault 1.18.5, 1.19.5 and 1.20.4 and
  OpenBao 2.0.0, 2.2.0, 2.4.0 and 2.7.2.

[Unreleased]: https://github.com/p-honik/vault-plugin-secrets-courier/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/p-honik/vault-plugin-secrets-courier/releases/tag/v0.1.0
