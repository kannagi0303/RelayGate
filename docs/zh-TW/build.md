# Build Guide

RelayGate 以 Windows 為優先。

## 需求

- Rust toolchain
- 如果要建置內嵌 Web UI，需要 pnpm

## 開發用建置

```bat
cargo build --release
```

這會建置預設的開發用 binary。

## Portable Binary 建置

如果需要 portable executable，可以建置 portable binary：

```bat
cargo build --release --bin relaygate-portable
```

Portable binary 會以執行檔所在目錄作為 runtime base directory，適合單檔使用情境。

## Frontend Notes

控制面板 frontend 位於 `frontend/`，會透過 build script 內嵌到 Rust binary。

完整建置前先安裝 frontend dependencies：

```bat
cd frontend
pnpm install
pnpm build
```

接著回到專案根目錄重新建置 RelayGate。

如果刻意跳過 frontend build，RelayGate 仍可提供 fallback embedded page，但完整控制面板體驗需要 frontend build。
