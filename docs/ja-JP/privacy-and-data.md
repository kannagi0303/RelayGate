# Privacy And Data

RelayGate は local-first です。

Runtime data は、RelayGate を実行したディレクトリの下に作成されます。

## Runtime Data

Runtime data には次のようなものが含まれます。

- ローカル設定
- logs
- DNS cache
- adblock data
- rewrite rules
- resource replacement files
- traffic state
- User Script files
- upstream proxy settings
- HTTPS MITM CA files

Runtime data は公開しないでください。

## CA Private Key

最も重要なデータは HTTPS MITM CA private key です。

RelayGate 自体が CA private key を送信したりアップロードしたりすることはありません。

この key は、HTTPS MITM が有効なときに、ローカルのブラウザ接続用証明書を作成するためにだけ使われます。

他人と共有しないでください。
アップロードしないでください。
公開しないでください。

## Logs

Logs には host names、URLs、request details、errors、runtime state が含まれることがあります。

公開する前に内容を確認し、個人情報や秘密情報を削除してください。

## Public Examples

公開例は小さく、中立的な内容にしてください。

個人的なルール、private upstream proxy addresses、private DNS routes、logs、CA files、local runtime state を公開しないでください。
