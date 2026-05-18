# Security Policy

RelayGate is a local proxy application. It may generate a local CA for HTTPS
MITM features.

## Reporting Security Issues

If you find a security issue, please do not post sensitive details in a public
issue.

Use GitHub private vulnerability reporting or GitHub Security Advisories if it
is available for this repository. If that is not available, open a public issue
with a short, non-sensitive summary and ask for a private contact path.

## Do Not Share Private Runtime Data

Do not include these in public reports:

- CA private keys
- `data/state/mitm/`
- private logs, diagnostics, and generated state under `data/state/`
- private proxy routes
- private DNS routes under `data/user/settings.yaml > dns`
- private User Scripts under `data/user/user_script/`
- private rewrite, patch, or replacement rules under `data/user/`

Logs can contain host names, URLs, request details, and local runtime state.
Review and redact them before sharing.

## Local CA Note

RelayGate itself does not transmit or upload the CA private key.

The CA private key is used locally so RelayGate can create certificates for the
local browser connection when HTTPS MITM is enabled.

Do not share it with other people. Do not upload it. Do not publish it.
