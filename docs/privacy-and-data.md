# Privacy And Data

RelayGate is local-first.

Runtime data is created on your machine under the directory where RelayGate
runs.

## Data Layout

User-owned data and user intent live under:

```text
data/user/
```

RelayGate-generated persistent state lives under:

```text
data/state/
```

Bundled resources and fallback seeds live under:

```text
assets/
```

## User-Owned Data

User-owned data can include:

- DNS config
- upstream proxy settings
- rewrite rules
- patch rules
- resource replacement files
- User Script files
- user adblock custom rules and subscription settings

Keep user-owned data private unless you intentionally want to share it.

## RelayGate State

RelayGate-generated state can include:

- logs and diagnostics
- DNS cache and learned state
- observed origin connection health
- downloaded adblock lists
- adblock matcher cache
- traffic state
- HTTPS MITM CA files

Keep generated state private.

## CA Private Key

The most sensitive data is the HTTPS MITM CA private key under `data/state/mitm/`.

RelayGate itself does not transmit or upload the CA private key.

The key is used locally to create certificates for the local browser connection
when HTTPS MITM is enabled.

Do not share it with other people.
Do not upload it.
Do not publish it.

## Logs

Logs may contain host names, URLs, request details, errors, and runtime state.

Do not publish logs without reviewing them.

## Sharing Snippets

When sharing config snippets or rule snippets, keep them small and neutral.

Do not publish personal rules, private upstream proxy addresses, private DNS
routes, logs, CA files, or local runtime state.
