# Configuration Guide

RelayGate 使用一個很小的 root config，加上使用者擁有的 settings 檔。

## Root Config

啟動層級設定放在 root 檔案：

```text
relaygate.yaml
```

目前 root config 欄位：

- `listen.host`
- `listen.port`
- `dns_server.enabled`
- `dns_server.host`
- `dns_server.port`
- `locale`

預設值：

```text
listen.host = 127.0.0.1
listen.port = 8787
locale = en-US

dns_server.enabled = false
dns_server.host = inherit listen.host
dns_server.port = 53
```

`dns_server` 可以整段省略。省略時不會啟動 `53` port 的 DNS Server。需要 RelayGate 作為本地 DNS Server 時，請明確設定 `dns_server.enabled = true`。

## User Settings Store

使用者擁有的設定放在：

```text
data/user/settings.yaml
```

這個 store 可以包含：

- adblock mode
- upstream protocol preference
- downstream protocol preference
- upstream proxy profiles and routes
- DNS servers and DNS routes
- local rules

## DNS Config

DNS 使用者意圖儲存在：

```text
data/user/settings.yaml > dns
```

使用者可見的 DNS section 會保存 DNS servers 與 host routes。

DNS routes 在內部永遠是 strict。DNS route 必須指向明確的 UDP DNS server profile。Route target 不能是 `system` 或 `auto`。

內建 `system` DNS profile 仍可用於安全的 RelayGate proxy/internal resolution。DNS Server ingress 不會使用 System DNS 作為 upstream。

## DNS State

RelayGate 產生的 DNS state 放在：

```text
data/state/dns.bin
```

這個 binary state file 會保存：

- DNS cache snapshot
- learned DNS health information

DNS auto-select 的 runtime choice 只存在記憶體，不是使用者設定。

RelayGate 也會把 TCP origin connection health 放在：

```text
data/state/origin_connect_health.bin
```

這是低頻率 lazy snapshot，用來保存觀察到的 IPv4 / IPv6 連線健康度，避免重啟後完全冷啟動。它是 RelayGate 產生的 state，必要時可以刪除。

## User Script Data

User Script source files 放在：

```text
data/user/user_script/*.user.js
```

RelayGate 產生的 User Script metadata 與 enable state 放在：

```text
data/state/user_script.bin
```

`data/user/settings.yaml` 不應包含 `user_script` section。

## User-Owned Data

使用者擁有的資料與使用者意圖放在：

```text
data/user/
```

這可以包含 settings、rewrite rules、patch rules、resource replacement rules、User Script source files，以及使用者 adblock 設定。

## RelayGate State

RelayGate 產生的持久狀態放在：

```text
data/state/
```

這可以包含 DNS state、下載的 adblock data、matcher cache、diagnostics、learned state，以及 HTTPS MITM CA 檔案。

不要公開 runtime configs、logs、本地 CA 檔案或私人規則。

請看 [Privacy And Data](./privacy-and-data.md)。
