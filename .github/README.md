# RelayGate

RelayGate is a web proxy for Windows.

It supports:

- Local HTTP and HTTPS proxy
- Traffic control by host
- Adblock support (based on `brave/adblock-rust`)
- Rule-based patch support
- Rule-based rewrite support


<img src="flow.png" width="300"/>

## What RelayGate does

- Proxy HTTP and HTTPS traffic
- Control web traffic
- Block ads
- Patch responses with rules
- Rewrite pages with rules

## What works now

- Traffic Control
  - Queue a host after HTTP `429` (too many requests in a short time)
  - Learn cooldown and release interval per host

- Adblock
  - Based on [brave/adblock-rust](https://github.com/brave/adblock-rust).
  - Good performance
  - Supports common filter rules
  - Supports cosmetic filtering
  - Supports resource replace and redirect
  - Supports HTML injection for page filtering

- Patch
  - Change response data for supported sites
  - Patch JSON-based responses with rules

- Rewrite
  - Change page output for supported sites
  - Extract page data and render with templates

## Get Started

Choose the guide that fits your use case:

- [Usage Guide](../docs/usage.md)
  For users who want to run RelayGate and use it in a browser or system proxy setup.

- [Build Guide](../docs/build.md)
  For developers who want to build RelayGate from source.

- [Configuration Guide](../docs/configuration.md)
  For app settings, proxy settings, and feature options.

- [Docs Index](../docs/README.md)
  For the full documentation list.

## Requirements

- Windows
- Rust if you want to build from source

## Notes

- RelayGate can start even if some `data/` folders do not exist yet.
- Some features may be limited if related data files are missing.
- If you use HTTPS MITM, your device or browser must trust the RelayGate local CA.

## Author

- Kannagi
- I try to use simple words so more people can read this project more easily.
- For questions, suggestions, comments, or discussion, please use GitHub Issues or Discussions.
- You can write in English, Chinese, or Japanese.

## License

- RelayGate is licensed under `MPL-2.0`.
