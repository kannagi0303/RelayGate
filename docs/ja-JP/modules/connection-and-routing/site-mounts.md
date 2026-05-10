# Site Mounts

## このモジュールでできること

Site Mounts モジュールは、リモートサイトを RelayGate のローカルパス配下に公開します。

たとえば、リモートサイトを `/site/` のようなローカルパスに mount できます。

## 使う場面

RelayGate の通常 pipeline を通してリモートサイトを取得し、ローカル URL path の下で表示したいときに使います。

controlled access、testing、proxy-side rewriting、local gateway behavior の実験に向いています。

## 仕組み

RelayGate は local mount path へのリクエストを受け取り、target remote site を取得します。link rewriting が有効な場合は、可能な範囲でリンクを mount path 配下に戻します。

site mount には、任意で upstream proxy profile を指定できます。

## 注意点

Link rewriting は best effort です。

複雑なサイトでは、absolute URLs、scripts、service workers、runtime navigation patterns などにより、すべてを mount path 配下に維持できない場合があります。

## 関連ドキュメント

- [Site Mounts](../../../site-mounts.md)
- [Upstream Proxies](./upstream-proxies.md)
