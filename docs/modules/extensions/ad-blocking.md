# Ad Blocking

## What It Does

The Ad Blocking module blocks ads, trackers, and unwanted requests from the local proxy path.

RelayGate uses `adblock-rust`, the Rust adblock engine used by Brave's native ad blocker.

## When To Use It

Use this module when you want RelayGate to reduce unwanted network requests before they reach the browser.

It is useful for ad blocking, tracker blocking, known unwanted resources, and document filtering on mutable pages.

## How It Works

RelayGate loads adblock rules and checks matching requests during the local proxy flow.

When HTTPS MITM is enabled and the document is mutable, RelayGate can also apply document-level filtering and cosmetic injection.

## Notes

Ad blocking can break some sites.

If a site depends on ad or tracker requests for playback, login, or page state, you may need to disable or adjust rules for that site.

## Related Docs

- [Features](../../features.md)
- [Known Limitations](../../known-limitations.md)
