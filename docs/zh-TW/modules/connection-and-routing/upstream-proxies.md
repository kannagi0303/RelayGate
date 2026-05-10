# Upstream Proxies

## 這個模組做什麼

Upstream Proxies 模組用來定義 RelayGate 連到網站時可以使用的外部 proxy profiles。

upstream proxy profile 代表一條可用的對外路徑。它本身不決定哪個網站要使用這條路徑。

## 什麼時候適合使用

當你希望 RelayGate 保留一個或多個 upstream proxy 位址時，可以使用這個模組。

這適合用在「只有指定網站走另一個 proxy，其餘網站保持直連」的情境。

## 它大致如何運作

RelayGate 會把 upstream proxy profiles 存在本地，並套用到新的對外請求。

目前支援的 upstream proxy 位址格式是 `http://host:port`。

要指定哪些 host 使用某個 profile，請搭配 Upstream Rules。

## 注意事項

變更會套用到新的請求。既有對外連線可能會自然結束後才完全切換。

## 相關文件

- [Upstream Rules](./upstream-rules.md)
- [設定說明](../../../configuration.md)
