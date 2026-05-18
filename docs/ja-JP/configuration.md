# Configuration Guide

RelayGate は小さな root config と、user-owned settings files を使います。

## Root Config

Startup-level settings は root file に置きます。

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

`dns_server` は省略できます。省略した場合、port `53` の DNS Server listener は起動しません。RelayGate を local DNS Server として使う場合は、`dns_server.enabled = true` を明示してください。

## User Settings Store

User-owned settings は次の場所に置きます。

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

DNS user intent は次の section に保存されます。

```text
data/user/settings.yaml > dns
```

User-facing DNS section は DNS servers と host routes を保存します。

DNS routes は内部的に常に strict です。DNS route は explicit UDP DNS server profile を指す必要があります。Route target に `system` や `auto` は使えません。

Built-in `system` DNS profile は、安全な RelayGate proxy/internal resolution では使えます。DNS Server ingress は System DNS を upstream として使いません。

## DNS State

RelayGate-generated DNS state は次の場所に置きます。

```text
data/state/dns.bin
```

This binary state file stores:

- DNS cache snapshot
- learned DNS health information

DNS auto-select の runtime choice は memory-only です。User setting ではありません。

RelayGate also keeps TCP origin connection health here:

```text
data/state/origin_connect_health.bin
```

This is a low-frequency lazy snapshot of observed IPv4 / IPv6 connection health. It helps RelayGate avoid a completely cold start after restart. It is RelayGate-generated state and can be deleted if needed.

## User Script Data

User Script source files は次の場所に置きます。

```text
data/user/user_script/*.user.js
```

RelayGate-generated User Script metadata and enable state は次の場所に置きます。

```text
data/state/user_script.bin
```

`data/user/settings.yaml` should not contain a `user_script` section.

## User-Owned Data

User-owned data と user intent は次の場所に置かれます。

```text
data/user/
```

Settings、rewrite rules、patch rules、resource replacement rules、User Script source files、user adblock settings などが含まれます。

## RelayGate State

RelayGate が生成する persistent state は次の場所に置かれます。

```text
data/state/
```

DNS state、downloaded adblock data、matcher cache、diagnostics、learned state、HTTPS MITM CA files などが含まれます。

runtime configs、logs、local CA files、private rules を公開しないでください。

[Privacy And Data](./privacy-and-data.md) を見てください。
