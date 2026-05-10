# Page Reconstruction

## What It Does

The Page Reconstruction module rebuilds output from extracted data.

It is for cases where a simple patch is not enough and RelayGate should extract data first, then render a new response from a local template.

## When To Use It

Use this module when the target page is better handled as extract-and-render instead of direct response patching.

It is useful for controlled views, simplified pages, parser-like output, or template-based local replacement.

## How It Works

RelayGate applies extraction rules, prepares data, and renders output through local templates when the request matches the rule path.

## Notes

Page reconstruction is more invasive than page patching.

It should be used for cases where the desired output is intentionally different from the original page.

## Related Docs

- [Rewrite Rules](../../rewrite-rules.md)
- [Page Patching](./page-patching.md)
