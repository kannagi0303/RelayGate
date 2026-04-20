# Configuration

Main example:

- [relaygate.example.yaml](../relaygate.example.yaml)

## Sections

- `app`
- `proxy`
- `web`
- `tray`
- `traffic`
- `logging`
- `gateway`
- `upstreams`
- `rules`

## app

- `name`: app name

## proxy

- `listen`: proxy listen address. Default: `0.0.0.0:8787`
- `mitm.enabled`: turn HTTPS MITM on or off
- `mitm.tolerate_invalid_upstream_cert_hosts`: hosts that may skip the upstream TLS check
- `adblock.enabled`: turn adblock on or off
- `adblock.mode`: adblock mode
- `adblock.auto_update`: allow auto update for filter data

## web

- `listen`: web listen address. Default: `0.0.0.0:8788`
- `open_browser_on_launch`: open the web page at start

## tray

- `enabled`: turn Windows tray on or off

## traffic

- `enabled`: turn traffic control on or off
- `max_queue_per_host`: max queued requests for one host
- `initial_cooldown_secs`: first cooldown time
- `initial_release_interval_secs`: first release interval
- `min_cooldown_secs`: min cooldown time
- `max_cooldown_secs`: max cooldown time
- `min_release_interval_secs`: min release interval
- `max_release_interval_secs`: max release interval
- `auto_adjust_step_secs`: auto adjust step
- `auto_relax_after_successes`: success count before relax
- `internal_retry_limit`: internal retry count

## logging

- `log_response_body`: log response body or not

## gateway

- `mounts`: gateway mount list

## upstreams

- Upstream server list

## rules

- Rule list for routing and behavior
