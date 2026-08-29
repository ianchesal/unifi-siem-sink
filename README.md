# UniFi SIEM Sink

A fake SIEM that you can ship your Unifi UDM logs to and then point AI to analyze the logs.

Unifi does not expose the IDP logs and events via there API which means using
AI to analyze events is hard. This sink service can be configured as a SIEM in
the UDM control plane. It captures the incoming logs and events, storing them
with a TTL. It provides an MCP interface to an AI that it can use to analyze
these logs and events.

## Quick Start (Official Docker Image)

No published Docker image exists yet — no release has been cut for this
project. Once a release process is in place (see the sibling
`unifi-mcp-server` project for the pattern to follow — it has an established
release/publish workflow this project can adopt), this section will point at
a pre-built image on a registry. Until then, use
[Run with Docker Compose](#run-with-docker-compose) below to build and run
the image locally.

## Tools

MCP tools exposed by this server for an AI client to query stored events:

| Tool | Description |
|---|---|
| `list_events` | List stored UniFi SIEM events. Filters: since/until (ISO8601 timestamps, filtered on receipt time), category, severity_min, source_ip/dest_ip (exact match or CIDR, e.g. "10.0.30.0/24"), limit (default 100, max 500), offset. |
| `get_event` | Get a single stored event by id, including its full raw syslog message. |
| `get_categories` | List the distinct event categories currently present in the store (e.g. "ips_alert", "firewall_block", "honeypot", "admin_action", "unknown"). |
| `get_event_stats` | Get aggregate event counts grouped by category, severity, or source_ip, optionally within a time range (since/until, ISO8601). |

---

## Development (Running from a Repo Clone)

### Setup

```bash
npm install
cp .env.example .env
```

Edit `.env` and set `MCP_SECRET` to a strong, unique value — this is the
secret an MCP client must present to talk to this server. The other
variables in `.env.example` (ports, DB path, retention, log level) have
sensible defaults and can be left as-is for local development.

### Run with Docker Compose

```bash
docker compose up -d --build
```

This builds the image (see `Dockerfile`) and starts the container, exposing:

- `3000/tcp` for the MCP/HTTP server (health checks, MCP endpoint)
- `514/udp` (mapped to the container's `10514/udp`) for incoming syslog/CEF traffic

Once it's running, configure the UDM Pro to ship its logs here: in the UniFi
controller, go to **Network > Settings > System Logging** (or **Integrations
> SIEM export**, depending on controller version) and point the remote
syslog / SIEM destination at this host's IP address on port `514`.

Event data persists in the `siem-data` named volume, backed by SQLite at
`/data/events.db` inside the container.

### Run locally

```bash
npm run build && npm start
```

This compiles TypeScript to `dist/` and runs the compiled server with
`node dist/index.js` — the same path used in the Docker image.

**Known issue — `npm run dev` is currently broken on Node 24.x and 25.x.**
The `dev` script (`node --experimental-strip-types src/index.ts`, with
`NODE_OPTIONS=--experimental-sqlite` for Node < 23.4) is intended to run the
TypeScript source directly in watch mode without a build step. However, on
this project's tested Node versions (v24.10.0 and v25.8.2), it fails with
`ERR_MODULE_NOT_FOUND`: Node's `--experimental-strip-types` flag does not
resolve `.js`-suffixed relative imports against sibling `.ts` files the way
`tsc` does. This is a pre-existing limitation also present in the sibling
`unifi-mcp-server` project's identical `dev` script — it is not unique to
this codebase. Until that's resolved (e.g. by adopting a tool like `tsx`, or
if the sibling project's convention changes), use `npm run build && npm
start` for local runs, rebuilding after each change.

### Integration tests (requires real UDM Pro)

This test tier does not exist yet. No confirmed live traffic has been
captured from a real UDM Pro against this parser (see the design doc's Open
Questions) — the current test suite runs entirely against synthetic and
recorded CEF fixtures. Real integration tests should be added once actual
CEF samples are captured from a live UDM Pro, especially Security-category
events (IPS/IDS alerts, honeypot hits), so that fixtures can be built from
genuine device output rather than assumptions about its format.
