# User Scripts

## What It Does

The User Scripts module manages local `.user.js` files and injects matching scripts into mutable HTML documents.

This is compatible local User Script support for scripts in the Tampermonkey / ScriptCat style.

## When To Use It

Use this module when you want RelayGate to run local scripts from the proxy path instead of relying only on a browser userscript manager.

It is useful for small page behavior changes, local helpers, and scripts that can work inside RelayGate's compatible injection model.

## How It Works

RelayGate scans local `.user.js` files, reads userscript metadata, and tracks enabled scripts.

Matching enabled scripts are injected into future mutable HTML document responses.

## Notes

This is compatibility support, not full Tampermonkey or ScriptCat parity.

Some userscript APIs may be unsupported or implemented differently. Pages loaded before enabling a script should be reloaded.

## Related Docs

- [User Script Guide](../../user-script.md)
- [HTTPS MITM And CA](../../https-mitm-and-ca.md)
