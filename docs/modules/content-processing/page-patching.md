# Page Patching

## What It Does

The Page Patching module applies focused edits to upstream responses.

It is meant for small, targeted changes such as JSON field cleanup, HTML fragments, JavaScript value replacement, or response header changes.

## When To Use It

Use this module when a page only needs a narrow change instead of a full page reconstruction.

It is useful for fixing specific values, removing small fragments, or adjusting a response without replacing the whole document.

## How It Works

RelayGate loads patch rules from the local rule path and applies them to mutable responses when the request matches.

After editing rules outside RelayGate, reload rewrite rules from the control panel.

## Notes

Page patching only applies to content RelayGate can safely treat as mutable.

Range responses and `206 Partial Content` responses are not mutated.

## Related Docs

- [Rewrite Rules](../../rewrite-rules.md)
- [Page Reconstruction](./page-reconstruction.md)
