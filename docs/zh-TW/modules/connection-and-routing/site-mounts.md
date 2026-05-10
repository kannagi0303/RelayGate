# Site Mounts

## 這個模組做什麼

Site Mounts 模組可以把遠端網站掛載到 RelayGate 的本地路徑底下。

例如，某個遠端網站可以被掛載到像 `/site/` 這樣的本地路徑。

## 什麼時候適合使用

當你希望 RelayGate 透過正常本地 pipeline 抓取遠端網站，並把它呈現在本地 URL 路徑底下時，可以使用這個模組。

這適合用在受控存取、測試、proxy-side rewrite，或本地 gateway 行為實驗。

## 它大致如何運作

RelayGate 收到本地 mount path 的請求後，會抓取目標遠端網站，並在啟用時盡量把連結改寫回 mount path 底下。

site mount 也可以選擇使用特定 upstream proxy profile。

## 注意事項

Link rewriting 是 best effort。

複雜網站可能使用 absolute URLs、scripts、service workers 或 runtime navigation patterns，這些不一定能完全維持在 mount path 底下。

## 相關文件

- [Site Mounts](../../../site-mounts.md)
- [Upstream Proxies](./upstream-proxies.md)
