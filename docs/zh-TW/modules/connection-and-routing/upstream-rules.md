# Upstream Rules

## 這個模組做什麼

Upstream Rules 模組用來指定特定 host 應該使用哪個 upstream proxy profile。

它是在 upstream proxy 清單之上，提供 per-site routing 的模組。

## 什麼時候適合使用

當某些網站要走 upstream proxy，而其他網站要保持直連時，可以使用這個模組。

它適合用來快速測試網站是否應該走代理，而不需要改整個瀏覽器的 proxy 設定。

## 它大致如何運作

RelayGate 會把 host rules 套用到 request host。

規則可以使用 `example.com`、`www.example.com`、`*.example.com` 這類 pattern。

符合規則的請求可以被送到指定的 upstream proxy profile。

## 注意事項

規則依 host 評估，並套用到新的請求。

如果某個 upstream proxy profile 被刪除，指向它的 rule 可能會變成 missing，直到重新調整。

## 相關文件

- [Upstream Proxies](./upstream-proxies.md)
- [DNS](./dns.md)
