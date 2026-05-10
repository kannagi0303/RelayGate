# Features

這份文件列出 RelayGate 更完整的能力。

## 使用者可感知功能

- 本地 Windows proxy。
- 使用本地 CA 的 HTTPS MITM。
- 廣告阻擋與 document filtering。
- 用本地規則修改頁面與資源。
- 用本地檔案替換資源。
- 相容型本地 User Scripts，包含 Tampermonkey / ScriptCat 風格腳本。
- DNS profiles、DNS cache，以及 host-based DNS routes。
- upstream proxy profiles 與 per-site routing。
- 透過 local gateway 使用 site mounts。
- traffic scheduling，用來控制請求爆發。
- 本地 Web 控制面板。
- Windows tray 控制。

## 模組說明

如果你想按照本地 Web 控制面板的模組來理解功能，請看 [模組說明](./modules/README.md)。

## 協議與傳輸能力

這些是較底層的能力，適合想知道 RelayGate 能處理什麼的使用者。

- HTTP proxy requests。
- HTTPS CONNECT tunnel。
- HTTP Upgrade 後的 WebSocket bridge。
- HTTP/1 handling。
- downstream HTTP/2 MITM handling。
- 有 fallback 保護的 upstream HTTP/3 path。
- Range 與 `206 Partial Content` passthrough。
- 支援路徑上的 request body streaming。

## 內容處理能力

當功能路徑允許時，RelayGate 可以處理可修改的 HTTP 與 HTTPS 文件。

- request blocking。
- request header rewrite。
- response body rewrite。
- HTML patch rules。
- JSON patch rules。
- template-based page reconstruction。
- local file resource replacement。
- adblock cosmetic 與 document injection。
- 將 User Script 注入可修改的 HTML documents。

Range 與 `206 Partial Content` responses 不會被修改。

## Routing 與 DNS

RelayGate 可以使用本地規則處理 DNS 與 upstream proxy routing。

- upstream proxy profiles。
- host wildcard upstream routes。
- DNS profiles。
- host wildcard DNS routes。
- DNS cache。
- negative cache。
- stale fallback。
- system DNS fallback。

## Traffic Scheduling

Traffic scheduling 是本地請求控制功能。

它可以在遇到 `429 Too Many Requests` 後，降低同站點後續請求爆發，並使用 cooldown state 減少對同一網站的重複壓力。

請看 [Traffic Scheduling](./traffic-scheduling.md)。

## Site Mounts

Site mounts 讓 RelayGate 可以透過 local gateway，把遠端網站放到本地路徑底下。

請看 [Site Mounts](./site-mounts.md)。

## Beta 限制

請看 [Known Limitations](./known-limitations.md)。
