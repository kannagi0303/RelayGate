# Ad Blocking

## 這個模組做什麼

Ad Blocking 模組會從本地 proxy 路徑阻擋廣告、追蹤器，以及不想要的請求。

RelayGate 使用 `adblock-rust`，這是 Brave 內建廣告阻擋器使用的 Rust adblock engine。

## 什麼時候適合使用

當你希望 RelayGate 在請求進入瀏覽器之前，就先減少不想要的網路請求時，可以使用這個模組。

它適合用來阻擋廣告、追蹤器、已知不想要的資源，以及在可修改頁面上套用 document filtering。

## 它大致如何運作

RelayGate 會載入 adblock rules，並在本地 proxy 流程中檢查請求是否符合規則。

當 HTTPS MITM 啟用，且文件內容可以修改時，RelayGate 也可以套用 document-level filtering 與 cosmetic injection。

## 注意事項

Ad blocking 可能讓部分網站行為異常。

如果某個網站依賴廣告或追蹤請求來完成播放、登入或頁面狀態更新，你可能需要針對該網站停用或調整規則。

## 相關文件

- [Features](../../../features.md)
- [Known Limitations](../../../known-limitations.md)
