# Browser Proxy Setup

RelayGate 通常更適合透過瀏覽器層級的 proxy 設定來使用。

這樣可以把 RelayGate 限制在你選擇的瀏覽器中，也比較容易開關，不會改動整個 Windows 網路環境。

## 推薦：瀏覽器 Proxy 擴充套件

對 Chrome、Brave、Edge，以及其他 Chromium-based browsers，建議使用瀏覽器 proxy 管理擴充套件。

RelayGate 主要使用以下工具進行開發與測試：

- Proxy SwitchyOmega 3 (ZeroOmega)

其他 proxy 管理擴充套件也可能可以使用，例如：

- FoxyProxy
- Proxyverse

建立一個 proxy profile：

- Protocol: HTTP
- Host: `127.0.0.1`
- Port: `8787`

然後在瀏覽器中啟用這個 profile。

## 為什麼不建議 Windows 全域 Proxy？

Windows 全域 proxy 設定可能影響比你預期更多的應用程式。

這可能讓系統 app、啟動器、更新工具、背景程式都經過 RelayGate。

對大多數使用者來說，瀏覽器層級 proxy 設定更容易控制。

只有在你理解影響範圍，並且真的想要 system-wide proxy 行為時，才建議使用 Windows 全域 proxy。

## 選用：Chrome Command Line

進階使用者也可以用 proxy flag 啟動 Chromium-based browsers。

例如：

```bat
chrome.exe --proxy-server=http://127.0.0.1:8787
```

這適合臨時測試，但日常使用通常還是 proxy extension 比較方便。

## Firefox

Firefox 有自己的 proxy 設定。

你可以直接設定 Firefox，不需要改 Windows 全域 proxy。

設定：

- HTTP Proxy: `127.0.0.1`
- Port: `8787`
- Also use this proxy for HTTPS: enabled
