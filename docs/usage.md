# Usage

Use this file after RelayGate is built.

## Default Ports

- Proxy: `0.0.0.0:8787`
- Web: `0.0.0.0:8788`

## Start

1. Start RelayGate.
2. Set your browser or app to use RelayGate as a proxy.
3. Use `localhost:8787` or your machine IP with port `8787`.

## Open The Web Page

Use one of these:

- `http://127.0.0.1:8788/`
- `http://localhost:8788/`
- `http://<your-ip>:8788/`

If your browser is already using RelayGate as a proxy, these may also work:

- `http://127.0.0.1:8787/`
- `http://localhost:8787/`
- `http://rg.local/`
- `http://rg.localhost/`

Notes:

- `0.0.0.0` is a listen address.
- In a browser, do not open `0.0.0.0`.

## HTTPS And Local CA

If you use HTTPS MITM, RelayGate may create a local CA (Certificate Authority) in:

- `data/mitm/`

This local CA lets RelayGate create site certificates for HTTPS traffic.

Important:

1. Your device or browser must trust this local CA.
2. RelayGate uses this CA to sign site certificates for the client side.
3. The client side will not see the target site's real certificate directly.

## Upstream TLS Check

RelayGate still checks the target site's certificate by default.

This means:

- Trusting the local RelayGate CA does not disable the upstream TLS check.
- If the target site's certificate is invalid, RelayGate should treat it as an error.
- RelayGate may return its own error page to say the upstream certificate is invalid.

## Invalid Upstream Certificate Whitelist

You can allow some hosts to bypass the upstream TLS check:

- `proxy.mitm.tolerate_invalid_upstream_cert_hosts`

Use this only for hosts that you trust.

## Notes

- If some data files are missing, RelayGate may still start.
- In that case, some features may not work.
