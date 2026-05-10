# User Scripts

## 這個模組做什麼

User Scripts 模組用來管理本地 `.user.js` 檔案，並把符合條件的 scripts 注入可修改的 HTML documents。

這是針對 Tampermonkey / ScriptCat 風格 scripts 的相容型本地 User Script 支援。

## 什麼時候適合使用

當你希望 RelayGate 從 proxy 路徑執行本地腳本，而不只依賴瀏覽器 userscript manager 時，可以使用這個模組。

它適合小型頁面行為調整、本地輔助腳本，以及能在 RelayGate 相容注入模型中運作的 scripts。

## 它大致如何運作

RelayGate 會掃描本地 `.user.js` 檔案、讀取 userscript metadata，並記錄哪些 scripts 已啟用。

符合條件且已啟用的 scripts 會被注入未來載入的可修改 HTML document responses。

## 注意事項

這是相容型支援，不等於完整 Tampermonkey 或 ScriptCat 相容。

某些 userscript APIs 可能不支援，或以不同方式實作。啟用 script 前已載入的頁面需要重新載入。

## 相關文件

- [User Script Guide](../../../user-script.md)
- [HTTPS MITM 與 CA](../../../https-mitm-and-ca.md)
