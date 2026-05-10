# Build Guide

RelayGate is Windows-first.

## Requirements

- Rust toolchain
- pnpm, if you want to build the embedded web UI

## Build For Development

```bat
cargo build --release
```

This builds the default development binary.

## Build The Portable Binary

To build a portable executable, use the portable binary target:

```bat
cargo build --release --bin relaygate-portable
```

The portable binary uses the executable directory as its runtime base directory.
This target is useful when you want RelayGate to use the executable directory as its runtime directory.

## Frontend Notes

The control panel frontend is built from `frontend/` and embedded into the Rust
binary by the build script.

Install frontend dependencies before a full embedded UI build:

```bat
cd frontend
pnpm install
pnpm build
```

Then build RelayGate again from the project root.

If the frontend build is intentionally skipped, RelayGate can still provide a
fallback embedded page, but the full control panel experience needs the frontend
build.
