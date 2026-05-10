# Usage Guide

## 啟動 RelayGate

執行：

```bat
relaygate.exe
```

預設 RelayGate 監聽：

```text
127.0.0.1:8787
```

開啟本地控制面板：

```text
http://127.0.0.1:8787/
```

不要瀏覽 `0.0.0.0`。它是 listen address，不是瀏覽器地址。

## 設定瀏覽器 Proxy

可以的話，請使用瀏覽器層級 proxy 設定。

推薦測試工具：

- Proxy SwitchyOmega 3 (ZeroOmega)

Proxy profile：

- Protocol: HTTP
- Host: `127.0.0.1`
- Port: `8787`

請看 [Browser Proxy Setup](./browser-proxy-setup.md)。

## HTTPS MITM

部分 HTTPS 功能需要 HTTPS MITM 與受信任的本地 CA。

RelayGate 可以產生本地 CA，並安裝到 Windows Current User Root certificate store。

請看 [HTTPS MITM And CA](./https-mitm-and-ca.md)。

## Control Panel

本地控制面板可以顯示與管理：

- runtime status
- adblock settings
- DNS profiles and routes
- upstream proxy profiles and routes
- resource replacement rules
- User Script scan status
- traffic state
- gateway mounts
- CA status
- protocol preferences

有些設定可能需要重新啟動或重新連線後，所有流量路徑才會使用新值。
