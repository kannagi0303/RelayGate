# Rewrite Rules

RelayGate 可以用本地規則修改頁面與資源。

這個功能適合想做本地頁面修改，但不想為每個案例寫瀏覽器擴充套件的使用者。

## Rules 能做什麼

Rules 可以用於：

- request matching
- response body rewrite
- HTML patching
- JSON patching
- template-based page reconstruction
- local file resource replacement

## Rules 放在哪裡

Runtime rewrite data 是本地私有資料。

常見 runtime folders：

```text
data/rewrite/
data/resource_replace/
```

除非是打算公開的範例，否則不要公開私人 rule files。

## HTTPS Sites

需要 HTTPS 頁面內容的 rules 需要 HTTPS MITM。

瀏覽器必須信任 RelayGate local CA，HTTPS MITM 才能不出現憑證警告。

請看 [HTTPS MITM And CA](./https-mitm-and-ca.md)。

## Limits

- Range 與 `206 Partial Content` responses 不會被修改。
- Binary resources 應使用 resource replacement 或 passthrough behavior。
- Site-specific rules 可能在目標網站改版後失效。
