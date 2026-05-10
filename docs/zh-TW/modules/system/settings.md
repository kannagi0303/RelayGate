# Settings

## 這個模組做什麼

Settings 模組用來管理 RelayGate 常用的執行設定。

它包含協議偏好、CA 信任動作、語言選擇、安全的 reload 動作，以及關閉 RelayGate 的操作。

## 什麼時候適合使用

當你想調整 RelayGate 連線方式、管理本地 CA、重新載入本地規則，或安全地關閉 RelayGate 時，可以使用這個模組。

## 它大致如何運作

保存設定時，RelayGate 會寫入本地設定檔。

部分設定只會套用到新的連線。已存在的瀏覽器連線或 upstream 連線，可能會自然結束後才完全反映新設定。

## 注意事項

設定 hot reload 不等於重新啟動所有 listener 或既有連線。

如果協議或 listener 相關設定沒有立刻反映，請重新連線瀏覽器，或重新啟動 RelayGate。

## 相關文件

- [HTTPS MITM 與 CA](../../../https-mitm-and-ca.md)
- [設定說明](../../../configuration.md)
- [Known Limitations](../../../known-limitations.md)
