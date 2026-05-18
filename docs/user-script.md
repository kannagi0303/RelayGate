# User Script Guide

RelayGate can run compatible local User Scripts.

This is compatibility support for Tampermonkey / ScriptCat style scripts. It is
not full Tampermonkey or ScriptCat parity.

## How It Works

RelayGate scans local `.user.js` files and checks their metadata.

When a page matches the script rules, RelayGate can inject the script into a
mutable HTML document.

HTTPS pages need HTTPS MITM before RelayGate can inject scripts into them.

## Local Files

Runtime User Script files are local data.

Typical folder:

```text
data/user/user_script/
```

Scripts should be reviewed before use.

## Compatibility

Supported or partially supported areas can include:

- metadata scan
- URL matching
- injection timing for supported paths
- local compatibility shims for selected APIs
- local storage style value support for compatible scripts

Unsupported APIs may be stubbed or warned.

## Limits

- This is not full browser-extension parity.
- Some scripts depend on extension-only APIs.
- Some scripts depend on page timing that may not match RelayGate injection.
- Dynamic sites may need special rules or may not work.
