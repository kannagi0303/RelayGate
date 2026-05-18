# User Script Guide

RelayGate は compatible local User Scripts を実行できます。

これは Tampermonkey / ScriptCat 風 scripts の compatibility support です。完全な Tampermonkey / ScriptCat parity ではありません。

## How It Works

RelayGate は local `.user.js` files を scan し、metadata を確認します。

page が script rules に match すると、RelayGate は mutable HTML document に script を inject できます。

HTTPS pages に script を inject するには HTTPS MITM が必要です。

## Local Files

Runtime User Script files は local data です。

Typical folder:

```text
data/user/user_script/
```

Scripts は使う前に review してください。

## Compatibility

Supported または partially supported areas:

- metadata scan
- URL matching
- supported paths の injection timing
- selected APIs の local compatibility shims
- compatible scripts の local storage style value support

Unsupported APIs は stub または warning になる場合があります。

## Limits

- full browser-extension parity ではありません。
- 一部 scripts は extension-only APIs に依存します。
- 一部 scripts は RelayGate injection と一致しない page timing に依存します。
- Dynamic sites は special rules が必要な場合、または動かない場合があります。
