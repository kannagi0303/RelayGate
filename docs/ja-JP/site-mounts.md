# Site Mounts

Site mounts は local gateway 経由で remote site を local path 配下に公開します。

Example idea:

```text
/local-site/  ->  https://example.com/
```

local testing、controlled routing、gateway-style access to a remote site に使えます。

## Behavior

mount can define:

- local mount path
- target base URL
- optional upstream proxy profile
- link rewrite behavior
- minimal fetch behavior

## Limits

Site mounts は gateway feature です。

Dynamic sites は origin checks、cookies、scripts、CORS behavior、または extra handling が必要な absolute links に依存する場合があります。
