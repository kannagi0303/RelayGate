# Resource Replace

## What It Does

The Resource Replace module replaces matched remote resources with local files.

It can swap scripts, stylesheets, images, or other matched resources before the request reaches the upstream server.

## When To Use It

Use this module when a known remote resource should be served from a local file instead.

It is useful for testing, patching frontend assets, replacing broken resources, or keeping a controlled local copy of a resource.

## How It Works

RelayGate checks resource replacement rules during the local proxy flow.

When a request matches a rule, RelayGate serves the configured local file instead of fetching the remote resource.

## Notes

If a rule points to a local file that does not exist, the rule should be treated as invalid and should be fixed.

Rule toggles can apply hot. If files were edited outside RelayGate, reload resource rules from the control panel.

## Related Docs

- [Rewrite Rules](../../rewrite-rules.md)
- [Features](../../features.md)
