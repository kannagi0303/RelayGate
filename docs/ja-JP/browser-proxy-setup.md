# Browser Proxy Setup

RelayGate は通常、ブラウザ単位の proxy 設定で使う方が簡単です。

RelayGate を選んだブラウザだけに限定できます。また、Windows 全体のネットワーク環境を変えずにオン/オフしやすくなります。

## Recommended: Browser Proxy Extension

Chrome、Brave、Edge、その他 Chromium-based browsers では、browser proxy manager extension を推奨します。

RelayGate は主に次のツールで開発・テストされています。

- Proxy SwitchyOmega 3 (ZeroOmega)

他の proxy manager extensions も使える場合があります。

- FoxyProxy
- Proxyverse

proxy profile を作成します。

- Protocol: HTTP
- Host: `127.0.0.1`
- Port: `8787`

その profile をブラウザで有効にします。

## Windows Global Proxy を推奨しない理由

Windows global proxy settings は、想定より多くのアプリに影響することがあります。

system apps、launchers、update tools、background apps が RelayGate 経由になる可能性があります。

多くのユーザーには browser-level proxy setup の方が制御しやすいです。

system-wide proxy behavior が必要で、その影響を理解している場合だけ Windows global proxy を使ってください。

## Optional: Chrome Command Line

上級ユーザーは proxy flag 付きで Chromium-based browsers を起動できます。

例:

```bat
chrome.exe --proxy-server=http://127.0.0.1:8787
```

一時的なテストには便利ですが、日常利用には browser extension の方が簡単です。

## Firefox

Firefox には独自の proxy settings があります。

Windows global proxy settings を変えずに Firefox を直接設定できます。

設定:

- HTTP Proxy: `127.0.0.1`
- Port: `8787`
- Also use this proxy for HTTPS: enabled
