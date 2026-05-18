# Configuration Guide

RelayGate uses a small root config plus user-owned settings files.

## Root Config

Startup-level settings live in the root file:

```text
relaygate.yaml
```

Current root config fields:

- `listen.host`
- `listen.port`
- `dns_server.enabled`
- `dns_server.host`
- `dns_server.port`
- `locale`

Defaults:

```text
listen.host = 127.0.0.1
listen.port = 8787
locale = en-US

dns_server.enabled = false
dns_server.host = inherit listen.host
dns_server.port = 53
```

`dns_server` can be omitted. Omitted DNS Server config means the port `53` listener is disabled. Set `dns_server.enabled = true` explicitly when you want RelayGate to act as a local DNS Server.

## User Settings Store

User-owned settings live under:

```text
data/user/settings.yaml
```

This store can include:

- adblock mode
- upstream protocol preference
- downstream protocol preference
- upstream proxy profiles and routes
- DNS servers and DNS routes
- local rules

## DNS Config

DNS user intent is stored inside:

```text
data/user/settings.yaml > dns
```

The user-facing DNS section stores DNS servers and host routes.

DNS routes are strict internally. A DNS route must point to an explicit UDP DNS server profile. Route targets cannot be `system` or `auto`.

The built-in `system` DNS profile can still be used by RelayGate proxy/internal resolution where it is safe. DNS Server ingress does not use System DNS as an upstream.

## DNS State

RelayGate-generated DNS state lives in:

```text
data/state/dns.bin
```

This binary state file stores:

- DNS cache snapshot
- learned DNS health information

DNS auto-select runtime choice is kept in memory. It is not a user setting.

RelayGate also keeps TCP origin connection health under:

```text
data/state/origin_connect_health.bin
```

This file is a low-frequency lazy snapshot of observed IPv4 / IPv6 connection health. It helps RelayGate avoid a completely cold start after restart. It is RelayGate-generated state and can be deleted if needed.

## User Script Data

User Script source files live in:

```text
data/user/user_script/*.user.js
```

RelayGate-generated User Script metadata and enable state live in:

```text
data/state/user_script.bin
```

`data/user/settings.yaml` should not contain a `user_script` section.

## User-Owned Data

User-owned data and user intent live under:

```text
data/user/
```

This can include settings, rewrite rules, patch rules, resource replacement rules, User Script source files, and user adblock settings.

## RelayGate State

RelayGate-generated persistent state lives under:

```text
data/state/
```

This can include DNS state, downloaded adblock data, matcher cache, diagnostics, learned state, and HTTPS MITM CA files.

Do not publish runtime configs, logs, local CA files, or private rules.

See [Privacy And Data](./privacy-and-data.md).
