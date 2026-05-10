# Known Limitations

RelayGate is still a beta project.

## HTTPS MITM

- HTTPS MITM can break some sites.
- Some apps and browsers use their own trust store.
- A trusted RelayGate local CA is needed for browser-trusted HTTPS MITM.
- Plain CONNECT tunnel mode does not need the RelayGate CA.

## User Scripts

- User Script support is compatibility support.
- It is not full Tampermonkey or ScriptCat parity.
- Some extension-only APIs are not available.
- Some scripts may depend on timing or page behavior that RelayGate cannot match.

## HTTP/3

- HTTP/3 is used only as a guarded upstream path with fallback.
- It is not full end-to-end HTTP/3 support.
- Downstream browser-to-RelayGate HTTP/3 is not a release target.

## WebSocket

- WebSocket payloads are bridged.
- RelayGate does not parse or rewrite WebSocket message payloads.

## Range And Partial Content

- Range and `206 Partial Content` responses are passed through.
- RelayGate does not mutate these response bodies.

## Settings Reload

- Some settings are saved but may need restart or reconnect before all paths use them.
- Listener and protocol changes may not fully hot-reload in this beta.

## Windows Builds

- Unsigned Windows builds may show a SmartScreen warning.
- Download from the official repository or build from source.
