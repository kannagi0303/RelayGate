# Browser Proxy Setup

RelayGate is usually easier to use from browser-level proxy settings.

This keeps RelayGate limited to the browser you choose. It also makes it easier
to turn RelayGate on or off without changing the whole Windows network
environment.

## Recommended: Browser Proxy Extension

For Chrome, Brave, Edge, and other Chromium-based browsers, a browser proxy
manager extension is recommended.

RelayGate was developed and tested mainly with:

- Proxy SwitchyOmega 3 (ZeroOmega)

Other proxy manager extensions may also work, such as:

- FoxyProxy
- Proxyverse

Create a proxy profile:

- Protocol: HTTP
- Host: `127.0.0.1`
- Port: `8787`

Then enable that profile for the browser.

## Why Not Windows Global Proxy?

Windows global proxy settings can affect more apps than you expect.

This may route system apps, launchers, update tools, and background apps through
RelayGate.

For most users, browser-level proxy setup is easier to control.

Use Windows global proxy only if you understand the effect and want system-wide
proxy behavior.

## Optional: Chrome Command Line

Advanced users can also launch Chromium-based browsers with a proxy flag.

Example:

```bat
chrome.exe --proxy-server=http://127.0.0.1:8787
```

This is useful for temporary testing, but a browser extension is usually easier
for daily use.

## Firefox

Firefox has its own proxy settings.

You can configure Firefox directly without changing Windows global proxy
settings.

Use:

- HTTP Proxy: `127.0.0.1`
- Port: `8787`
- Also use this proxy for HTTPS: enabled
