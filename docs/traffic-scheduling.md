# Traffic Scheduling

Traffic scheduling is a local request control feature.

It is designed to reduce repeated pressure on the same site when RelayGate sees
request bursts or `429 Too Many Requests` responses.

## Current Behavior

RelayGate can keep cooldown state per site.

When a site returns `429 Too Many Requests`, RelayGate can slow down later
same-site requests and release queued work more gradually.

This is a beta feature. Behavior may change as the scheduler becomes smarter.

## What It Is Not

Traffic scheduling is not a bandwidth booster.

It does not make a remote server faster.

It only helps RelayGate avoid sending repeated bursts when a site is already
asking the client to slow down.
