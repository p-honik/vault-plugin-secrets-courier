# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the API (paths, parameters, stored data and token
claims) may change in a minor release. Such changes are listed under **Changed**
or **Removed**, and changes to the storage format are called out explicitly.

## [Unreleased]

## [0.1.2] - 2026-11-07

### Fixed

- A `request/<role>` call that had read the config just before a `courier/config`
  write could replace the network policy that write had installed, re-opening a
  network the admin had just denied until the next request. The write now
  invalidates the cache before installing its policy, and a request only applies
  a policy built from a config no older than the last write.

## [0.1.1] - 2026-11-02

### Added

- A warning, logged once, when a `request/<role>` request reaches a backend that
  has already been cleaned up (unmount or step-down). Such a request is dropped
  with the usual `204`; before, nothing was logged.

### Fixed

- A panic in the `request/<role>` handler after its in-flight slot was reserved
  (for example while reading or using the key set) no longer leaks the slot. The
  reservation and the `min_request_interval` timer are now released on every
  early exit, so repeated panics cannot exhaust `max_inflight` or lock a
  requester out until the next restart.

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

[Unreleased]: https://github.com/p-honik/vault-plugin-secrets-courier/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/p-honik/vault-plugin-secrets-courier/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/p-honik/vault-plugin-secrets-courier/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/p-honik/vault-plugin-secrets-courier/releases/tag/v0.1.0
