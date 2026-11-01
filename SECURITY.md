# Security policy

Courier handles credentials, so please report vulnerabilities privately and do
not open a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab of this
repository and choose **Report a vulnerability**. Include the plugin version
(`vault plugin info secret vault-plugin-secrets-courier`), the Vault or OpenBao
version, and steps to reproduce.

You can expect an acknowledgement within a few days. Fixes are released as a new
version and described in [CHANGELOG.md](CHANGELOG.md); the report is disclosed
once a fixed version is available.

## Supported versions

Only the latest release receives security fixes. While the version is below 1.0.0
a fix may arrive together with a breaking change; the changelog says so.

## Scope

In scope: the plugin in this repository, including secrets leaking through
responses, logs or the audit log, bypass of the receipt URL allowlist or the
network policy, and token forgery. Vulnerabilities in Vault, OpenBao or other
dependencies should be reported to their maintainers.
