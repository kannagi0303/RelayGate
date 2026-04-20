# Build

Use this file if you want to build RelayGate from source.

## Need

- Windows
- Rust

## Steps

1. Open PowerShell in the project folder.
2. Run:

```powershell
cargo run
```

3. Wait for RelayGate to build and start.

## Release Build

1. Open PowerShell in the project folder.
2. Run:

```powershell
cargo build --release
```

## Default Ports

- Proxy: `0.0.0.0:8787`
- Web: `0.0.0.0:8788`

Notes:

- `0.0.0.0` is a listen address.
- In a browser, use `localhost` or your machine IP.

## First Run

RelayGate can create these folders when needed:

- `data/logs/`
- `data/mitm/`
- `data/traffic/`

Notes:

- The app can still start if some `data/` folders are missing.
- In that case, some features may be limited.
