# Privacy And Data

RelayGate is local-first.

Runtime data is created on your machine under the directory where RelayGate
runs.

## Runtime Data

Runtime data can include:

- local settings
- logs
- DNS cache
- adblock data
- rewrite rules
- resource replacement files
- traffic state
- User Script files
- upstream proxy settings
- HTTPS MITM CA files

Keep runtime data private.

## CA Private Key

The most sensitive data is the HTTPS MITM CA private key.

RelayGate itself does not transmit or upload the CA private key.

The key is used locally to create certificates for the local browser connection
when HTTPS MITM is enabled.

Do not share it with other people.
Do not upload it.
Do not publish it.

## Logs

Logs may contain host names, URLs, request details, errors, and runtime state.

Do not publish logs without reviewing them.

## Public Examples

Public examples should be small and neutral.

Do not publish personal rules, private upstream proxy addresses, private DNS
routes, logs, CA files, or local runtime state.
