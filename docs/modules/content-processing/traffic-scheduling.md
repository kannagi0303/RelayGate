# Traffic Scheduling

## What It Does

The Traffic Scheduling module controls request bursts and same-site pressure.

It is designed to manage request admission, cooldown state, queueing, delayed retry, and release strategy.

## When To Use It

Use this module when a site returns `429 Too Many Requests`, or when repeated same-site requests should be slowed down.

It is useful for reducing repeated pressure on the same host.

## How It Works

RelayGate can learn cooldown state from runtime traffic and apply a slower release pattern for later requests to the same site.

The module is focused on request control. It does not modify response content.

## Notes

This is an early beta module.

Current behavior is intentionally conservative and should be treated as request scheduling support, not a complete rate-limit solution.

## Related Docs

- [Traffic Scheduling](../../traffic-scheduling.md)
- [Known Limitations](../../known-limitations.md)
