# User Script Guide

RelayGate 可以執行相容型本地 User Scripts。

這是針對 Tampermonkey / ScriptCat 風格腳本的相容支援，不等於完整 Tampermonkey 或 ScriptCat 相容。

## 運作方式

RelayGate 會掃描本地 `.user.js` 檔案並讀取 metadata。

當頁面符合腳本規則時，RelayGate 可以將腳本注入可修改的 HTML document。

HTTPS pages 需要 HTTPS MITM，RelayGate 才能注入腳本。

## Local Files

Runtime User Script files 是本地資料。

常見資料夾：

```text
data/user_script/
```

使用前應先檢查 scripts。

## Compatibility

支援或部分支援的範圍可能包含：

- metadata scan
- URL matching
- supported paths 上的 injection timing
- selected APIs 的 local compatibility shims
- compatible scripts 的 local storage style value support

Unsupported APIs 可能會被 stub 或警告。

## Limits

- 這不是完整 browser-extension parity。
- 某些 scripts 依賴 extension-only APIs。
- 某些 scripts 依賴 RelayGate injection 無法完全符合的 page timing。
- Dynamic sites 可能需要特殊規則，或無法運作。
