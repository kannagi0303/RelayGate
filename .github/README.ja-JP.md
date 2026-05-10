# RelayGate

RelayGate は、Windows を主な対象にしたローカル Proxy アプリケーションです。

ブラウザやアプリの手前に、ローカルのネットワーク制御レイヤーを置きます。
ブロック、ルーティング、DNS の挙動、HTTPS MITM、ページルール、リソース置換、
互換的なローカル User Script を扱えます。

RelayGate は、機能ごとにブラウザ拡張を増やすのではなく、手元の環境でまとめて制御したいユーザー向けです。

<img src="flow.png" width="300"/>

## RelayGate とは

RelayGate はあなたの PC 上で動作します。

ブラウザやアプリから使うローカル Proxy として動作し、通信がブラウザに届く前にローカルルールを適用できます。
そのため、ブロック、ルーティング、DNS 制御、ページ変更、リソース置換、互換的な User Script 注入に使えます。

基本的な Proxy 機能にブラウザ拡張は不要です。

## RelayGate でできること

RelayGate では次のようなことができます。

- ローカル Windows Proxy 経由でブラウズする。
- 広告、トラッカー、不要なリクエストをブロックする。
- ローカルルールでページやリソースを変更する。
- 条件に一致したリモートリソースをローカルファイルに置き換える。
- Tampermonkey / ScriptCat 風の互換的なローカル User Script を実行する。
- DNS キャッシュ、DNS profiles、host-based DNS routes を使う。
- 指定したサイトを upstream proxy profiles へルーティングする。
- リモートサイトをローカルパスの下にマウントする。
- traffic scheduling でリクエストの集中を制御する。
- ローカル CA を使って HTTPS MITM 機能を利用する。

日常操作用に、ローカル Web コントロールパネルと Windows tray 連携もあります。

詳しい機能一覧は [Features](../docs/ja-JP/features.md) を参照してください。

## RelayGate が HTTPS MITM を使う理由

RelayGate の一部の機能は、通常の Proxy tunnel だけで動作します。Tunnel モードでは、RelayGate は暗号化された HTTPS 通信を転送するだけで、ページ内容は読み取りません。

一方で、HTTPS ページやリソースにより深くアクセスする必要がある機能もあります。そのために RelayGate は HTTPS MITM を使うことがあります。

MITM は "man in the middle" の略です。ブラウザと実際の Web サイトの間に、別の処理主体が入る接続形態を指します。

MITM は強力ですが、それ自体が常に良いものとは限りません。マルウェアが MITM 技術を悪用して、データを盗んだり、内容を差し込んだり、プライベートな通信を監視したりすることがあります。

一方で、ユーザーが理解し許可している場合、ローカルのセキュリティツール、デバッグツール、開発用 Proxy、ペアレンタルコントロール、通信検査ツールでも MITM は使われます。

RelayGate が HTTPS MITM を使う目的は、次のようなローカル機能を提供するためです。

- page rules
- document filtering
- 変更可能な文書上での広告ブロック
- resource replacement
- 互換的な User Script injection
- ローカルでのデバッグと確認

RelayGate はオープンソースです。どのように動作するかをユーザー自身が確認できます。

安全のため、RelayGate はこの repository から入手するか、ソースから自分でビルドしてください。出所不明の第三者が配布する RelayGate 実行ファイルは実行しないでください。

## ローカル CA とブラウザの信頼

RelayGate は CA をインストールしなくても起動できます。

信頼済み CA がない場合でも、通常の tunnel proxy は動作します。ただし、HTTPS MITM にはブラウザの信頼が必要です。

HTTPS MITM が有効なとき、RelayGate はブラウザ向けにローカルのサイト証明書を作成します。ブラウザが RelayGate のローカル CA を信頼していない場合、警告を表示したり、その証明書を拒否したりします。

RelayGate はこのローカル CA を生成できます。

Windows では、RelayGate は現在のユーザーの Root certificate store に CA をインストールできます。Windows の信頼ストアを使うブラウザやアプリは、RelayGate が生成した証明書を信頼できるようになります。

一部のブラウザやアプリは独自の信頼ストアを使うため、別途設定が必要な場合があります。

CA private key はあなたの PC に残ります。RelayGate 自体が CA private key を送信したりアップロードしたりすることはありません。

この key は、HTTPS MITM が有効なときに、ローカルのブラウザ接続用証明書を作るためだけに使われます。

他人と共有しないでください。アップロードしないでください。公開しないでください。

詳しくは [HTTPS MITM And CA](../docs/ja-JP/https-mitm-and-ca.md) を参照してください。

## Quick Start

1. この repository から RelayGate をダウンロードするか、ソースからビルドします。
2. `relaygate.exe` を実行します。
3. ブラウザの Proxy を RelayGate に向けます。

```text
127.0.0.1:8787
```

ブラウザ単位の Proxy 設定をおすすめします。

RelayGate は主に Proxy SwitchyOmega 3 (ZeroOmega) で開発・テストしていますが、他のブラウザ用 Proxy 管理ツールも利用できます。

4. ローカルコントロールパネルを開きます。

```text
http://127.0.0.1:8787/
```

5. 必要に応じて、HTTPS MITM 機能のために RelayGate local CA をインストールします。

詳しくは [Browser Proxy Setup](../docs/ja-JP/browser-proxy-setup.md) を参照してください。

## Runtime Data

RelayGate は実行されたディレクトリの下に runtime data を作成することがあります。

これには、ローカル設定、logs、DNS cache、ルールデータ、HTTPS MITM CA ファイルなどが含まれます。

Runtime data、特に CA 関連ファイルは公開しないでください。

詳しくは [Privacy And Data](../docs/ja-JP/privacy-and-data.md) を参照してください。

## Documentation

- [Docs Index](../docs/ja-JP/README.md)
- [Features](../docs/ja-JP/features.md)
- [Modules](../docs/ja-JP/modules/README.md)
- [Browser Proxy Setup](../docs/ja-JP/browser-proxy-setup.md)
- [HTTPS MITM And CA](../docs/ja-JP/https-mitm-and-ca.md)
- [Usage Guide](../docs/ja-JP/usage.md)
- [Configuration Guide](../docs/ja-JP/configuration.md)
- [Rewrite Rules](../docs/ja-JP/rewrite-rules.md)
- [User Script Guide](../docs/ja-JP/user-script.md)
- [Privacy And Data](../docs/ja-JP/privacy-and-data.md)
- [Known Limitations](../docs/ja-JP/known-limitations.md)

## Known Limits

現在の制限は次のページにまとめています。

- [Known Limitations](../docs/ja-JP/known-limitations.md)

## Author

- Kannagi
- より多くの人が読みやすいように、できるだけシンプルな言葉で書くようにしています。
- 質問、提案、感想、議論は GitHub Issues または Discussions を利用してください。
- 英語、中国語、日本語で書いて構いません。

## License

RelayGate のソースコードは `MPL-2.0` ライセンスです。

このライセンスはソースコードに適用されます。プロジェクト名、マーク、ブランド権利を許諾するものではありません。
