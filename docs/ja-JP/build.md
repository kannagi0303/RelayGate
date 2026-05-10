# Build Guide

RelayGate は Windows を主な対象にしています。

## Requirements

- Rust toolchain
- 内蔵 Web UI をビルドする場合は pnpm

## 開発用ビルド

```bat
cargo build --release
```

これは標準の開発用 binary をビルドします。

## Portable Binary のビルド

Portable executable が必要な場合は、portable binary をビルドします。

```bat
cargo build --release --bin relaygate-portable
```

Portable binary は、実行ファイルがあるディレクトリを runtime base directory として使います。単一ファイルで使いたい場合に向いています。

## Frontend Notes

コントロールパネルの frontend は `frontend/` にあり、build script によって Rust binary に埋め込まれます。

完全な埋め込み UI をビルドする前に、frontend dependencies をインストールします。

```bat
cd frontend
pnpm install
pnpm build
```

その後、プロジェクトルートに戻って RelayGate をもう一度ビルドしてください。

Frontend build を意図的にスキップした場合でも fallback embedded page は利用できますが、完全なコントロールパネル体験には frontend build が必要です。
