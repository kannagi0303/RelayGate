# Known Limitations

RelayGate はまだ beta project です。

## HTTPS MITM

- HTTPS MITM は一部の sites を壊すことがあります。
- 一部の apps と browsers は独自の trust store を使います。
- browser-trusted HTTPS MITM には trusted RelayGate local CA が必要です。
- Plain CONNECT tunnel mode は RelayGate CA を必要としません。

## User Scripts

- User Script support は compatibility support です。
- full Tampermonkey / ScriptCat parity ではありません。
- 一部の extension-only APIs は使えません。
- 一部 scripts は RelayGate が一致させられない timing や page behavior に依存します。

## HTTP/3

- HTTP/3 は fallback 付きの guarded upstream path としてのみ使われます。
- full end-to-end HTTP/3 support ではありません。
- downstream browser-to-RelayGate HTTP/3 は release target ではありません。

## WebSocket

- WebSocket payloads は bridged されます。
- RelayGate は WebSocket message payloads を parse または rewrite しません。

## Range And Partial Content

- Range と `206 Partial Content` responses は passed through されます。
- RelayGate はこれらの response bodies を変更しません。

## Settings Reload

- 一部の settings は保存されますが、すべての paths が使うには restart または reconnect が必要な場合があります。
- Listener と protocol changes はこの beta で完全に hot-reload しない場合があります。

## Windows Builds

- unsigned Windows builds は SmartScreen warning を表示する場合があります。
- official repository から download するか、source から build してください。
