# Site Mounts

Site mounts 讓 RelayGate 可以透過 local gateway，把遠端網站放到本地路徑底下。

概念範例：

```text
/local-site/  ->  https://example.com/
```

這可用於本地測試、受控 routing，或透過 gateway-style 存取遠端網站。

## Behavior

一個 mount 可以定義：

- local mount path
- target base URL
- optional upstream proxy profile
- link rewrite behavior
- minimal fetch behavior

## Limits

Site mounts 是 gateway feature。

Dynamic sites 仍可能依賴 origin checks、cookies、scripts、CORS behavior，或需要額外處理的 absolute links。
