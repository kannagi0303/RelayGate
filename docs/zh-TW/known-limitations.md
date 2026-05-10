# Known Limitations

RelayGate 目前仍是 beta 專案。

## HTTPS MITM

- HTTPS MITM 可能讓某些網站無法正常運作。
- 某些應用程式與瀏覽器使用自己的 trust store。
- 若要讓瀏覽器信任 HTTPS MITM，需要受信任的 RelayGate local CA。
- Plain CONNECT tunnel mode 不需要 RelayGate CA。

## User Scripts

- User Script support 是相容支援。
- 它不是完整 Tampermonkey 或 ScriptCat 相容。
- 某些 extension-only APIs 無法使用。
- 某些 scripts 依賴 RelayGate 無法完全符合的 timing 或 page behavior。

## HTTP/3

- HTTP/3 只作為有 fallback 保護的 guarded upstream path 使用。
- 這不是完整 end-to-end HTTP/3 支援。
- Downstream browser-to-RelayGate HTTP/3 不是這次 release 目標。

## WebSocket

- WebSocket payloads 只做 bridge。
- RelayGate 不解析或改寫 WebSocket message payloads。

## Range And Partial Content

- Range 與 `206 Partial Content` responses 會 passthrough。
- RelayGate 不修改這些 response bodies。

## Settings Reload

- 某些設定會被保存，但可能需要 restart 或 reconnect 後，所有路徑才會使用。
- Listener 與 protocol changes 在這個 beta 中可能無法完整 hot-reload。

## Windows Builds

- 未簽章的 Windows builds 可能顯示 SmartScreen warning。
- 請從官方 repository 下載，或自行從原始碼編譯。
