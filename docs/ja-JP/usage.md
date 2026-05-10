# Usage Guide

## RelayGate を起動する

実行:

```bat
relaygate.exe
```

default では RelayGate は次で listen します。

```text
127.0.0.1:8787
```

ローカル control panel を開きます。

```text
http://127.0.0.1:8787/
```

`0.0.0.0` をブラウザで開かないでください。これは listen address であり、browser address ではありません。

## Browser Proxy を設定する

可能なら browser-level proxy setup を使ってください。

推奨テストツール:

- Proxy SwitchyOmega 3 (ZeroOmega)

Proxy profile:

- Protocol: HTTP
- Host: `127.0.0.1`
- Port: `8787`

[Browser Proxy Setup](./browser-proxy-setup.md) を見てください。

## HTTPS MITM

一部の HTTPS 機能には HTTPS MITM と trusted local CA が必要です。

RelayGate は local CA を生成し、Windows Current User Root certificate store にインストールできます。

[HTTPS MITM And CA](./https-mitm-and-ca.md) を見てください。

## Control Panel

ローカル control panel では次を表示・管理できます。

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

一部の設定は、すべての traffic paths で新しい値を使うために restart または reconnect が必要な場合があります。
