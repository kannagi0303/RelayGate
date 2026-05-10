# Page Reconstruction

## 這個模組做什麼

Page Reconstruction 模組會根據擷取出的資料重新產生輸出。

它適合用在 simple patch 不夠，需要先抽取資料，再用本地 template 產生新 response 的情境。

## 什麼時候適合使用

當目標頁面更適合用 extract-and-render，而不是直接 patch response 時，可以使用這個模組。

它適合受控視圖、簡化頁面、parser-like output，或 template-based local replacement。

## 它大致如何運作

RelayGate 會在 request 符合規則時套用 extraction rules、準備資料，並透過本地 templates render output。

## 注意事項

Page reconstruction 比 page patching 更具侵入性。

它應該用在你有意讓輸出和原始頁面不同的情境。

## 相關文件

- [Rewrite Rules](../../../rewrite-rules.md)
- [Page Patching](./page-patching.md)
