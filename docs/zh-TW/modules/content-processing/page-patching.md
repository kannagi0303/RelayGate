# Page Patching

## 這個模組做什麼

Page Patching 模組用來對 upstream response 做精準小修改。

它適合處理 JSON 欄位清理、HTML 片段、HTML 中的 JavaScript 值替換，或 response header 變更。

## 什麼時候適合使用

當頁面只需要局部調整，而不需要整頁重建時，可以使用這個模組。

它適合修正特定值、移除小片段，或在不替換整份 document 的情況下調整 response。

## 它大致如何運作

RelayGate 會從本地 rule path 載入 patch rules，並在 request 符合時套用到可修改的 responses。

如果你在 RelayGate 外部編輯規則，請從控制面板 reload rewrite rules。

## 注意事項

Page patching 只會套用在 RelayGate 可以安全視為 mutable 的內容上。

Range responses 與 `206 Partial Content` responses 不會被修改。

## 相關文件

- [Rewrite Rules](../../../rewrite-rules.md)
- [Page Reconstruction](./page-reconstruction.md)
