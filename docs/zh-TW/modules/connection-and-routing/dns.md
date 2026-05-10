# DNS

## 這個模組做什麼

DNS 模組用來管理 RelayGate 的 DNS profiles、DNS cache 行為，以及依 host 分流的 DNS routes。

它讓 RelayGate 可以決定由自己處理的請求要如何解析網域名稱。

## 什麼時候適合使用

當不同網站需要使用不同 DNS server、你想使用本地 DNS cache，或需要針對不穩定解析提供 fallback 時，可以使用這個模組。

## 它大致如何運作

RelayGate 可以透過 DNS profiles 與 host patterns，為新請求選擇 DNS 路徑。

DNS routes 可以匹配精確 host，也可以匹配 wildcard subdomains。RelayGate 也可以根據 runtime 行為保留 positive cache、negative cache 與 stale fallback 狀態。

## 注意事項

DNS 設定會套用到新的請求。

修改 DNS profiles 或 routes 後，舊的 cache 狀態應該會被清理，避免切換後還沿用過期解析結果。

這個模組只影響 RelayGate 自己解析的請求，不會取代 Windows 或其他應用程式的所有 DNS 查詢。

## 相關文件

- [Features](../../../features.md)
- [設定說明](../../../configuration.md)
