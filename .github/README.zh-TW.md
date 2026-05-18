# RelayGate

RelayGate 是一個以 Windows 為優先的本地 Proxy 應用程式。

它會在你的瀏覽器與應用程式前面，提供一層本地網路控制層：
阻擋、路由、DNS 行為、HTTPS MITM、頁面規則、資源替換，
以及相容型本地 User Script。

RelayGate 適合想要更多控制能力，但不想為每個功能都安裝瀏覽器擴充套件的使用者。

<img src="flow.png" width="300"/>

## RelayGate 是什麼

RelayGate 運行在你的電腦上。

它可以作為瀏覽器與應用程式使用的本地 Proxy，也可以在流量進入瀏覽器之前套用本地規則。
因此它可以用來處理阻擋、路由、DNS 控制、頁面修改、資源替換，以及相容型 User Script 注入。

核心 Proxy 功能不需要瀏覽器擴充套件。

## 你可以用 RelayGate 做什麼

RelayGate 可以幫你：

- 透過本地 Windows Proxy 瀏覽。
- 阻擋廣告、追蹤器，以及不想要的請求。
- 用本地規則修改頁面與資源。
- 將符合條件的遠端資源替換成本地檔案。
- 執行相容型本地 User Script，包含 Tampermonkey / ScriptCat 風格腳本。
- 使用 DNS 快取、DNS profiles，以及依 host 分流的 DNS routes。
- 將指定網站導向不同 upstream proxy profiles。
- 將遠端網站掛載到本地路徑底下。
- 使用 traffic scheduling 控制請求爆發。
- 透過本地 CA 使用 HTTPS MITM 功能。

RelayGate 也提供本地 Web 控制面板與 Windows tray 整合，方便日常操作。

完整能力清單請看：[Features](../docs/zh-TW/features.md)。

## RelayGate 如何使用 HTTPS MITM

RelayGate 的部分功能可以透過一般 Proxy tunnel 運作。在 tunnel 模式下，RelayGate 只會轉送加密的 HTTPS 流量，不讀取頁面內容。

但有些功能需要更深入地存取 HTTPS 頁面與資源。這些功能可以透過 HTTPS MITM 實現。

MITM 是 "man in the middle" 的縮寫。它描述的是：某一方位於瀏覽器與真實網站之間。

MITM 很強大，但它本身不一定是好東西。惡意軟體可能濫用 MITM 技術來竊取資料、注入內容，或監看私人流量。

但 MITM 也可以被本地安全工具、除錯工具、開發用 Proxy、家長控制工具，以及流量檢查工具使用——前提是使用者理解並允許。

RelayGate 使用 HTTPS MITM，只是為了提供本地功能，例如：

- page rules
- document filtering
- 可修改文件上的廣告阻擋
- resource replacement
- 相容型 User Script injection
- 本地除錯與檢查

RelayGate 是開源專案，因此使用者可以檢查它如何運作。

為了安全，請只從這個 repository 下載 RelayGate，或自行從原始碼編譯。不要執行從未知第三方取得的 RelayGate 執行檔。

## 本地 CA 與瀏覽器信任

RelayGate 可以在不安裝 CA 的情況下運行。

沒有受信任的 CA 時，一般 tunnel proxy 仍然可以運作。但是 HTTPS MITM 需要瀏覽器信任。

當啟用 HTTPS MITM 時，RelayGate 會為瀏覽器建立本地網站憑證。如果瀏覽器不信任 RelayGate 的本地 CA，就會顯示警告或拒絕這些憑證。

RelayGate 可以為你產生這組本地 CA。

在 Windows 上，RelayGate 可以將 CA 安裝到目前使用者的 Root certificate store。使用 Windows 信任存放區的瀏覽器與應用程式，之後就能信任 RelayGate 產生的憑證。

某些瀏覽器或應用程式可能使用自己的信任存放區，因此可能需要額外設定。

CA private key 會留在你的電腦上。RelayGate 本身不會傳輸或上傳 CA private key。

這把 key 只會在本機使用，用來讓 RelayGate 在啟用 HTTPS MITM 時，為本地瀏覽器連線建立憑證。

不要把它分享給其他人。不要上傳它。不要公開它。

詳細說明請看：[HTTPS MITM 與 CA](../docs/zh-TW/https-mitm-and-ca.md)。

## 快速開始

1. 從這個 repository 下載 RelayGate，或自行從原始碼編譯。
2. 執行 `relaygate.exe`。
3. 將瀏覽器設定為使用 RelayGate proxy：

```text
127.0.0.1:8787
```

建議使用瀏覽器層級的 proxy 設定。

RelayGate 主要使用 Proxy SwitchyOmega 3 (ZeroOmega) 進行開發與測試，但也可以使用其他瀏覽器 proxy 管理工具。

4. 開啟本地控制面板：

```text
http://127.0.0.1:8787/
```

5. 選用：安裝 RelayGate local CA，以使用 HTTPS MITM 功能。

請看：[瀏覽器 Proxy 設定](../docs/zh-TW/browser-proxy-setup.md)。

## Runtime Data

RelayGate 可能會在執行目錄下建立 runtime data。

使用者擁有的資料放在 `data/user/`。RelayGate 產生的狀態放在 `data/state/`。
這可能包含本地設定、logs、DNS cache、規則資料、下載的 adblock 資料、learned connection health、diagnostics，以及 HTTPS MITM CA 檔案。

請保持 runtime data 私有，尤其是 `data/state/mitm/` 底下的 CA 相關檔案。

詳細說明請看：[隱私與資料](../docs/zh-TW/privacy-and-data.md)。

## 文件

- [文件索引](../docs/zh-TW/README.md)
- [功能](../docs/zh-TW/features.md)
- [瀏覽器 Proxy 設定](../docs/zh-TW/browser-proxy-setup.md)
- [HTTPS MITM 與 CA](../docs/zh-TW/https-mitm-and-ca.md)
- [使用指南](../docs/zh-TW/usage.md)
- [設定指南](../docs/zh-TW/configuration.md)
- [Rewrite Rules](../docs/zh-TW/rewrite-rules.md)
- [User Script 指南](../docs/zh-TW/user-script.md)
- [隱私與資料](../docs/zh-TW/privacy-and-data.md)
- [已知限制](../docs/zh-TW/known-limitations.md)

## 已知限制

目前的限制整理在這裡：

- [已知限制](../docs/zh-TW/known-limitations.md)

## 作者

- Kannagi
- 我盡量使用簡單、容易閱讀的文字，讓更多人能看懂這個專案。
- 如果有問題、建議、感想或討論，請使用 GitHub Issues 或 Discussions。
- 可以使用英文、中文或日文。

## License

RelayGate 原始碼使用 `MPL-2.0` 授權。

這份授權涵蓋原始碼；不授予專案名稱、標誌或品牌使用權。
