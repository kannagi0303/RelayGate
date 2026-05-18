# DNS

## 這個模組做什麼

DNS 模組用來管理 RelayGate 自己使用的 DNS servers、依 host 分流的 DNS routes、cache 行為，以及 learned DNS health。

它控制通過 RelayGate 的請求要如何解析網域名稱。

## 什麼時候適合使用

當不同網站需要使用不同 DNS server、你想使用本地 DNS cache，或想讓 RelayGate 從 DNS health 中學習時，可以使用這個模組。

## 它大致如何運作

DNS 使用者意圖儲存在：

```text
data/user/settings.yaml > dns
```

RelayGate 產生的 DNS state 儲存在：

```text
data/state/dns.bin
```

`dns.bin` 會保存 DNS cache snapshots 與 learned DNS health state。

`origin_connect_health.bin` 會保存低頻率 lazy snapshot 的 TCP IPv4 / IPv6 origin connection health。DNS 只會把它當成 proxy/internal resolution 的軟性位址族偏好。

DNS routes 可以匹配精確 host，也可以匹配 wildcard subdomains。

DNS routes 在內部永遠是 strict。Route 必須指向明確的 UDP DNS server profile，不能指向 `system` 或 `auto`。

Proxy/internal resolution 在安全情境下仍可使用 System DNS。DNS Server ingress 不會使用 System DNS 作為 upstream。

## DNS Server

DNS Server 啟動設定放在 `relaygate.yaml` 的 `dns_server`。

預設行為：

```text
dns_server.enabled = false
dns_server.host = inherit listen.host
dns_server.port = 53
```

`dns_server` 可以整段省略。省略時 DNS Server listener 會保持停用；需要啟用時請明確設定 `dns_server.enabled = true`。

## 注意事項

DNS 設定會套用到新的請求。

修改 DNS servers 或 routes 後，舊的 cache 狀態應該會被清理，避免切換後還沿用過期解析結果。

這個模組會影響 RelayGate 自己解析的請求。除非 client 明確使用 RelayGate 的 DNS Server，否則不會取代 Windows 或其他應用程式的所有 DNS 查詢。

## 相關文件

- [Features](../../../features.md)
- [設定說明](../../../configuration.md)
