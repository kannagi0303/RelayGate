# Configuration Guide

RelayGate 使用本地設定檔。

## Main Config

主要設定檔：

```text
relaygate.yaml
```

公開範例：

```text
relaygate.example.yaml
```

常見設定包含：

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

公開範例：

```text
data/dns.example.yaml
```

Runtime file：

```text
data/dns.yaml
```

DNS config 可以包含：

- DNS profiles
- UDP DNS servers
- system DNS profile
- fallback profiles
- host-based DNS routes
- strict route behavior

## Upstream Proxy Config

公開範例：

```text
data/upstreams.example.yaml
```

Runtime file：

```text
data/upstreams.yaml
```

Upstream config 可以包含：

- upstream proxy profiles
- host pattern routes
- enable or disable flags

## Local Runtime Files

Runtime files 是私有本地資料。

不要公開 runtime configs、logs、本地 CA 檔案或私人規則。

請看 [Privacy And Data](./privacy-and-data.md)。
