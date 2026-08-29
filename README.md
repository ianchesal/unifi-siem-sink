# UniFi SIEM Sink

A fake SIEM that you can ship your Unifi UDM logs to and then point AI to analyze the logs.

Unifi does not expose the IDP logs and events via there API which means using
AI to analyze events is hard. This sink service can be configured as a SIEM in
the UDM control plane. It captures the incoming logs and events, storing them
with a TTL. It provides an MCP interface to an AI that it can use to analyze
these logs and events.

## Quick Start (Official Docker Image)

TODO(ianchesal): Write this section

## Tools

TODO: Write the MCP tools exposed by this server that AI can interact with

| Domain | Tools |
|---|---|
| Domain A | list/get action |

---

## Development (Running from a Repo Clone)

### Setup

TODO

### Run with Docker Compose

TODO

### Run locally

TODO

### Integration tests (requires real UDM Pro)

TODO
