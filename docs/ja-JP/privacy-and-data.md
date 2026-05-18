# Privacy And Data

RelayGate は local-first です。

Runtime data は RelayGate が実行されたディレクトリの下に作成されます。

## Data Layout

User-owned data と user intent は次の場所に置かれます。

```text
data/user/
```

RelayGate が生成する persistent state は次の場所に置かれます。

```text
data/state/
```

Bundled resources と fallback seeds は次の場所に置かれます。

```text
assets/
```

## User-Owned Data

User-owned data には次のようなものが含まれます。

- DNS config
- upstream proxy settings
- rewrite rules
- patch rules
- resource replacement files
- User Script files
- user adblock custom rules and subscription settings

意図して共有する場合を除き、user-owned data は private にしてください。

## RelayGate State

RelayGate-generated state には次のようなものが含まれます。

- logs and diagnostics
- DNS cache and learned state
- observed origin connection health
- downloaded adblock lists
- adblock matcher cache
- traffic state
- HTTPS MITM CA files

Generated state は private にしてください。

## CA Private Key

最も sensitive な data は `data/state/mitm/` 以下の HTTPS MITM CA private key です。

RelayGate 自体は CA private key を送信またはアップロードしません。

この key は、HTTPS MITM が有効なときに、local browser connection 用の certificate を作るためだけにローカルで使われます。

他人に共有しないでください。
アップロードしないでください。
公開しないでください。

## Logs

Logs には host names、URLs、request details、errors、runtime state が含まれることがあります。

公開する前に logs の内容を確認してください。

## Sharing Snippets

config snippets や rule snippets を共有するときは、小さく中立的な内容にしてください。

personal rules、private upstream proxy addresses、private DNS routes、logs、CA files、local runtime state を公開しないでください。
