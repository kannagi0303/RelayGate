# Architecture

RelayGate 是一個本地 proxy application，並帶有小型常駐控制介面。

## Main Flow

1. 瀏覽器或應用程式將流量送到 RelayGate。
2. RelayGate 套用本地 proxy、routing、DNS 與 rule decisions。
3. RelayGate 依情況 tunnel、forward，或處理 HTTPS MITM。
4. 可修改的 responses 可能經過 content processing。
5. 結果回傳給瀏覽器或應用程式。

## Main Areas

- proxy server
- CONNECT tunnel handling
- HTTPS MITM handling
- downstream HTTP/2 MITM handling
- upstream forwarding
- guarded upstream HTTP/3 path
- adblock engine
- rewrite and patch rules
- resource replacement
- local User Script injection
- DNS resolver and cache
- upstream proxy routing
- traffic scheduling
- gateway site mounts
- local web control panel
- Windows tray

## HTTPS MITM Boundary

HTTPS MITM 只在功能需要解密 HTTPS 內容時使用。

Plain tunnel mode 可以不讀取內容，直接轉送加密 HTTPS 流量。

## Runtime State

RelayGate 會把 runtime state 保存在本地。這可能包含 logs、DNS cache、traffic state、adblock data 與 CA files。

請看 [Privacy And Data](./privacy-and-data.md)。
