# HTTPS MITM And CA

這份文件說明 RelayGate 如何使用 HTTPS MITM 與本地 CA 檔案。

## MITM 是什麼

MITM 是 "man in the middle" 的縮寫。

它描述的是某一方位於瀏覽器與真實網站之間。

在 RelayGate 中，你的瀏覽器會先連到本機的 RelayGate，再由 RelayGate 代表你連到真正的網站。

## 為什麼 RelayGate 使用 MITM

一般 proxy tunnel 模式可以不讀取 HTTPS 內容，只轉送流量。

有些功能需要看到或修改 HTTPS 頁面與資源。這些功能可以透過 HTTPS MITM 實現。

例如：

- document filtering
- page rules
- 可修改文件上的廣告阻擋
- resource replacement
- 相容型 User Script injection
- 本地除錯與檢查

## MITM 很強大

MITM 不一定是好東西。

惡意軟體可能濫用 MITM 技術來竊取資料、注入內容，或監看私人流量。

但在使用者允許的情況下，MITM 也可以被本地安全工具、除錯 proxy、開發工具、家長控制工具與流量檢查工具使用。

RelayGate 使用 MITM 只為了提供本地功能。

RelayGate 是開源專案，使用者可以檢查它如何運作。為了安全，請只從這個 repository 下載 RelayGate，或自行從原始碼編譯。不要執行從未知第三方取得的 RelayGate 執行檔。

## 為什麼需要本地 CA

啟用 HTTPS MITM 時，RelayGate 會為瀏覽器建立本地網站憑證。

瀏覽器必須信任 RelayGate local CA。沒有這份信任時，瀏覽器可能顯示憑證警告或拒絕連線。

RelayGate 可以為你產生本地 CA。

在 Windows 上，RelayGate 可以將 CA 安裝到目前使用者的 Root certificate store。使用 Windows trust store 的瀏覽器與應用程式，之後就能信任 RelayGate 產生的憑證。

某些瀏覽器或應用程式會使用自己的 trust store，因此可能需要額外設定。

## CA Private Key 安全

CA private key 會留在你的電腦上。

RelayGate 本身不會傳輸或上傳 CA private key。

這把 key 只會在本機使用，用來讓 RelayGate 在啟用 HTTPS MITM 時，為本地瀏覽器連線建立憑證。

不要分享給其他人。
不要上傳。
不要公開。

如果你的 RelayGate CA 已安裝，取得這把 CA private key 的人可能建立被你的瀏覽器信任的憑證。

## Plain Tunnel Mode

RelayGate 可以在不安裝 CA 的情況下運行。

Plain CONNECT tunnel mode 不需要 RelayGate CA，因為在該模式下 RelayGate 不會解密 HTTPS 內容。

## Upstream Certificate Checks

RelayGate 預設仍會在 upstream 端檢查真實目標網站的憑證。

除非你理解影響，否則不要停用 upstream certificate checks。
