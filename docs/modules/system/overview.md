# Overview

## What It Does

The Overview module shows the current RelayGate runtime state.

It is a quick status page for the local proxy, loaded feature modules, DNS profiles, upstream proxies, site mounts, and basic environment information.

## When To Use It

Use this page when you want to know whether RelayGate is running normally and which major parts are loaded.

It is useful after startup, after changing rules, or after enabling new runtime features.

## How It Works

The page reads live backend summaries and shows them in one place. It does not own the detailed settings for each feature.

For detailed control, open the related module page.

## Notes

The Overview page is for status, not for deep traffic inspection.

Recent connection tracking and detailed logs may live in other tools or future pages.

## Related Docs

- [Features](../../features.md)
- [Known Limitations](../../known-limitations.md)
