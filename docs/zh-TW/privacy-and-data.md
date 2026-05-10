# 隱私與資料

RelayGate 以本地優先。

Runtime data 會建立在 RelayGate 執行所在的目錄下。

## Runtime Data

Runtime data 可能包含：

- 本地設定
- logs
- DNS cache
- adblock data
- rewrite rules
- resource replacement files
- traffic state
- User Script files
- upstream proxy settings
- HTTPS MITM CA files

請保持 runtime data 私有。

## CA Private Key

最敏感的資料是 HTTPS MITM CA private key。

RelayGate 本身不會傳輸或上傳 CA private key。

這把 key 只會在本機使用，用來在 HTTPS MITM 啟用時，為本地瀏覽器連線建立憑證。

不要把它分享給其他人。
不要上傳它。
不要公開它。

## Logs

Logs 可能包含 host names、URLs、request details、errors，以及 runtime state。

公開 logs 前請先檢查並移除私人資訊。

## Public Examples

公開範例應該保持小而中立。

不要公開個人規則、私人 upstream proxy addresses、私人 DNS routes、logs、CA files，或本地 runtime state。
