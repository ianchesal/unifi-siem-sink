# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP server that receives UniFi's CEF-over-syslog SIEM export (UDP), stores
it in SQLite with a retention window, and exposes it to an LLM over
Streamable HTTP. It exists because the UniFi Network Local API does not
expose IPS/IDS threat events (the `stat/ips/event` endpoint was removed in
firmware 10.x) — the SIEM/syslog export is the only remaining path to that
data. It pairs with the sibling project `unifi-mcp-server`, which covers
everything else in the UniFi Network API; this project fills only the
Security-category gap.

## Commands

```bash
npm run build        # tsc -> dist/
npm start             # node --env-file=.env dist/index.js (run after build)
npm test              # vitest run — full suite
npm run test:watch    # vitest watch mode
npm run lint           # biome check src
```

Run a single test file: `npx vitest run tests/parser/cef.test.ts`
Run tests matching a name: `npx vitest run -t "some test name"`

`npm run dev` (`node --experimental-strip-types src/index.ts`) is currently
broken on Node 24.x/25.x — `--experimental-strip-types` doesn't resolve
`.js`-suffixed relative imports against sibling `.ts` files the way `tsc`
does. Use `npm run build && npm start` for local runs instead, rebuilding
after each change.

Node >= 22.5.0 is required (uses `node:sqlite`, which is built in — no
better-sqlite3 or other native SQLite dependency).

Integration tests against a real UDM Pro don't exist yet; the suite runs
entirely against synthetic and recorded CEF fixtures in
`tests/fixtures/real-cef-samples.md`.

## Architecture

Startup wiring lives in `src/index.ts`: load config → open DB → start the
UDP syslog listener → start the Express/MCP HTTP server → register a
SIGTERM/SIGINT shutdown that drains all three in order. There's also a
setInterval-driven hourly purge of events older than `RETENTION_DAYS`.

Two independent ingress paths share the same SQLite database and never
otherwise interact:

- **Syslog ingestion** (`src/syslog/listener.ts`): a raw UDP socket
  (`dgram`) receives datagrams, oversized ones are dropped and counted
  (`droppedCount()`, surfaced at `/health`), and each message is parsed and
  inserted synchronously in the socket's `message` handler. Both parse and
  insert errors are swallowed there deliberately — this is a sink and must
  never stop listening because of one bad or unlucky message. The socket's
  runtime `error` event is likewise swallowed after bind (e.g. ICMP
  port-unreachable) for the same reason.
- **MCP query path** (`src/server.ts` + `src/tools/`): Express app with a
  Bearer-auth (`MCP_SECRET`) `POST /mcp` using
  `StreamableHTTPServerTransport` with `sessionIdGenerator: undefined`
  (stateless — a fresh `McpServer` + transport per request, closed on
  `res.close`). `/health` is unauthenticated and reports the listener's
  dropped-message count. Tools are registered in `src/tools/index.ts` →
  `registerAllTools`, currently just `registerEventTools` from
  `src/tools/events.ts` (`list_events`, `get_event`, `get_categories`,
  `get_event_stats` — see README for the exact filter semantics of each).

**Parsing pipeline** (`src/parser/index.ts`, `parseMessage`): three stages,
each of which can bail out to `unparsedEvent` (raw message preserved,
`parsed: 0`, `category: 'unknown'`) rather than throw — the raw syslog
message is always stored even when structure can't be extracted:
1. `envelope.ts` `stripEnvelope` — strips the syslog envelope to get at the
   CEF payload.
2. `cef.ts` `parseCef` — parses Common Event Format fields.
3. `normalize.ts` `normalize` — maps CEF fields onto the `EventRow` schema
   (falls back to a slugified `UNIFIcategory` for categories UniFi emits
   that aren't in the known mapping).

**Storage** (`src/storage/db.ts`): `node:sqlite`'s `DatabaseSync`, WAL mode,
incremental auto_vacuum. A numbered `MIGRATIONS` array applied in order and
tracked in a `schema_migrations` table — add new schema changes as a new
entry with the next `version`, never edit an already-applied migration.
`auto_vacuum = INCREMENTAL` must be set before any other pragma/statement
touches the database header (e.g. `journal_mode`); after that SQLite
silently ignores changes to it. `src/storage/cidr.ts` implements CIDR
matching used by the `list_events` `source_ip`/`dest_ip` filters.

## Config

All runtime config is env-driven, loaded and validated once in
`src/config.ts` (`loadConfig`) — fails fast if `MCP_SECRET` is unset or
`LOG_LEVEL` is invalid. See the README's Environment Variables table for
the full list and defaults; `DB_PATH` defaults differ between Docker
(`/data/events.db`, set by the image) and local runs (`./data/events.db`).
