# Privacy And Data

RelayGate 以本地優先為設計方向。

Runtime data 會建立在 RelayGate 執行目錄底下。

## Data Layout

使用者擁有的資料與使用者意圖放在：

```text
data/user/
```

RelayGate 產生的持久狀態放在：

```text
data/state/
```

程式附帶資源與 fallback seeds 放在：

```text
assets/
```

## User-Owned Data

使用者擁有的資料可以包含：

- DNS 設定
- upstream proxy settings
- rewrite rules
- patch rules
- resource replacement files
- User Script files
- user adblock custom rules and subscription settings

除非你確定要分享，否則請保持 user-owned data 私有。

## RelayGate State

RelayGate 產生的狀態可以包含：

- logs 與 diagnostics
- DNS cache 與 learned state
- observed origin connection health
- 下載的 adblock lists
- adblock matcher cache
- traffic state
- HTTPS MITM CA 檔案

請保持 generated state 私有。

## CA Private Key

最敏感的資料是 `data/state/mitm/` 底下的 HTTPS MITM CA private key。

RelayGate 本身不會傳輸或上傳 CA private key。

這把 key 只會在本機使用，用來讓 RelayGate 在啟用 HTTPS MITM 時，為本地瀏覽器連線建立憑證。

不要分享給其他人。
不要上傳。
不要公開。

## Logs

Logs 可能包含 host names、URLs、request details、errors，以及 runtime state。

發布 logs 前請先檢查內容。

## Sharing Snippets

分享 config snippets 或 rule snippets 時，請保持小而中立。

不要公開 personal rules、private upstream proxy addresses、private DNS routes、logs、CA files，或 local runtime state。
