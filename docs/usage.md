# Usage Guide

## Start RelayGate

Run:

```bat
relaygate.exe
```

By default, RelayGate listens on:

```text
127.0.0.1:8787
```

Open the local control panel:

```text
http://127.0.0.1:8787/
```

Do not browse to `0.0.0.0`. It is a listen address, not a browser address.

## Set Browser Proxy

Use browser-level proxy setup when possible.

Recommended test tool:

- Proxy SwitchyOmega 3 (ZeroOmega)

Proxy profile:

- Protocol: HTTP
- Host: `127.0.0.1`
- Port: `8787`

See [Browser Proxy Setup](./browser-proxy-setup.md).

## HTTPS MITM

Some HTTPS features need HTTPS MITM and a trusted local CA.

RelayGate can generate the local CA and install it into the Windows Current User
Root certificate store.

See [HTTPS MITM And CA](./https-mitm-and-ca.md).

## Control Panel

The local control panel can show and manage:

- runtime status
- adblock settings
- DNS profiles and routes
- upstream proxy profiles and routes
- resource replacement rules
- User Script scan status
- traffic state
- gateway mounts
- CA status
- protocol preferences

Some settings may need a restart or reconnect before all traffic paths use the
new value.
