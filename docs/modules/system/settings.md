# Settings

## What It Does

The Settings module manages common RelayGate runtime settings.

It covers protocol preferences, CA trust actions, language selection, safe reload actions, and shutdown actions.

## When To Use It

Use this page when you want to change how RelayGate connects to websites, manage the local CA, reload local rules, or exit RelayGate safely.

## How It Works

Saving settings writes to the local RelayGate configuration.

Some changes apply to new connections only. Existing browser or upstream connections may finish naturally before the new setting is fully visible.

## Notes

Settings hot reload is not the same as restarting every listener or connection.

If a protocol or listener-related change does not appear immediately, reconnect the browser or restart RelayGate.

## Related Docs

- [HTTPS MITM And CA](../../https-mitm-and-ca.md)
- [Configuration](../../configuration.md)
- [Known Limitations](../../known-limitations.md)
