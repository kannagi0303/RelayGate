# Architecture

RelayGate is a local proxy application with a small resident control surface.

## Main Flow

1. A browser or app sends traffic to RelayGate.
2. RelayGate applies local proxy, routing, DNS, and rule decisions.
3. RelayGate either tunnels traffic, forwards it, or handles HTTPS MITM.
4. Mutable responses may pass through content processing.
5. The result is returned to the browser or app.

## Main Areas

- proxy server
- CONNECT tunnel handling
- HTTPS MITM handling
- downstream HTTP/2 MITM handling
- upstream forwarding
- guarded upstream HTTP/3 path
- adblock engine
- rewrite and patch rules
- resource replacement
- local User Script injection
- DNS resolver and cache
- upstream proxy routing
- traffic scheduling
- gateway site mounts
- local web control panel
- Windows tray

## HTTPS MITM Boundary

HTTPS MITM is used only when a feature needs decrypted HTTPS content.

Plain tunnel mode can pass encrypted HTTPS traffic without reading the content.

## Runtime State

RelayGate keeps runtime state locally. This can include logs, DNS cache, traffic
state, adblock data, and CA files.

See [Privacy And Data](./privacy-and-data.md).
