# DNS

## このモジュールでできること

DNS モジュールでは、RelayGate-owned DNS servers、host-based DNS routes、cache behavior、learned DNS health を管理します。

RelayGate を通る request の domain name resolution を制御します。

## 使う場面

サイトごとに違う DNS server を使いたいとき、local DNS cache を使いたいとき、RelayGate に DNS health から学習させたいときに使います。

## 仕組み

DNS user intent は次の場所に保存されます。

```text
data/user/settings.yaml > dns
```

RelayGate-generated DNS state は次の場所に保存されます。

```text
data/state/dns.bin
```

`dns.bin` stores DNS cache snapshots and learned DNS health state.

`origin_connect_health.bin` stores a low-frequency lazy snapshot of observed TCP IPv4 / IPv6 origin connection health. DNS uses this as a soft address-family preference for proxy/internal resolution only.

DNS routes は exact host や wildcard subdomains に一致できます。

DNS routes は内部的に常に strict です。Route は explicit UDP DNS server profile を指す必要があります。`system` や `auto` は指定できません。

Proxy/internal resolution では安全な場合に System DNS を使えます。DNS Server ingress は System DNS を upstream として使いません。

## DNS Server

DNS Server startup settings は `relaygate.yaml` の `dns_server` にあります。

Default behavior:

```text
dns_server.enabled = false
dns_server.host = inherit listen.host
dns_server.port = 53
```

`dns_server` は省略できます。省略した場合 DNS Server listener は disabled のままです。有効にする場合は `dns_server.enabled = true` を明示してください。

## 注意点

DNS 設定は新しいリクエストに適用されます。

DNS servers や routes を変更した場合、古い cache state は再利用されないように消去されるべきです。

このモジュールは RelayGate が解決する requests に影響します。Clients が RelayGate の DNS Server を明示的に使わない限り、Windows や他の apps のすべての DNS lookup を置き換えるものではありません。

## 関連ドキュメント

- [Features](../../../features.md)
- [Configuration](../../../configuration.md)
