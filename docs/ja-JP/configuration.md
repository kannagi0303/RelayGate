# Configuration Guide

RelayGate は local configuration files を使います。

## Main Config

Main config file:

```text
relaygate.yaml
```

Public example:

```text
relaygate.example.yaml
```

Common settings:

- proxy listen address
- web control panel listen address
- HTTPS MITM settings
- adblock mode
- upstream protocol preference
- downstream protocol preference
- traffic scheduling settings
- gateway mounts
- local rules

## DNS Config

Public example:

```text
data/dns.example.yaml
```

Runtime file:

```text
data/dns.yaml
```

DNS config can include:

- DNS profiles
- UDP DNS servers
- system DNS profile
- fallback profiles
- host-based DNS routes
- strict route behavior

## Upstream Proxy Config

Public example:

```text
data/upstreams.example.yaml
```

Runtime file:

```text
data/upstreams.yaml
```

Upstream config can include:

- upstream proxy profiles
- host pattern routes
- enable or disable flags

## Local Runtime Files

Runtime files は private local data です。

runtime configs、logs、local CA files、private rules を公開しないでください。

[Privacy And Data](./privacy-and-data.md) を見てください。
