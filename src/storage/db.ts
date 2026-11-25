import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { EventRow } from '../parser/normalize.js';
import { reparseClientEvents } from './reparseClientEvents.js';

export interface Db {
  conn: DatabaseSync;
  close(): void;
}

// A migration runs its `sql` (if any), then its `run` code step (if any), in one transaction.
// A string returned by `run` is logged. Code steps use the parser as of when they run, not as of
// when they were written.
interface Migration {
  version: number;
  sql?: string;
  run?: (conn: DatabaseSync) => string | undefined;
}

const MIGRATIONS: Migration[] = [
  {
    version: 1,
    sql: `
      CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        received_at TEXT NOT NULL,
        event_time TEXT,
        category TEXT NOT NULL DEFAULT 'unknown',
        subcategory TEXT,
        severity INTEGER,
        name TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        source_port INTEGER,
        dest_port INTEGER,
        protocol TEXT,
        action TEXT,
        signature TEXT,
        message TEXT,
        device_host TEXT,
        raw TEXT NOT NULL,
        parsed INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX idx_events_received_at ON events(received_at);
      CREATE INDEX idx_events_category ON events(category);
      CREATE INDEX idx_events_source_ip ON events(source_ip);
      CREATE INDEX idx_events_dest_ip ON events(dest_ip);
    `,
  },
  {
    // UniFi client identity for events that name a LAN client by alias/hostname/MAC.
    version: 2,
    sql: `
      ALTER TABLE events ADD COLUMN source_client_name TEXT;
      ALTER TABLE events ADD COLUMN source_client_mac TEXT;
      ALTER TABLE events ADD COLUMN dest_client_name TEXT;
      ALTER TABLE events ADD COLUMN dest_client_mac TEXT;
    `,
  },
  {
    // Re-parse rows stored before Security events stopped falling back to UNIFIdeviceIp.
    version: 3,
    run: (conn) => {
      const r = reparseClientEvents(conn);
      return `Migration 3: re-parsed client events: ${r.updated} rows updated, ${r.sourceIpChanged} source_ip corrected`;
    },
  },
  {
    // unifi-siem-lens looks events up by client MAC (it opens the DB read-only, so the
    // index has to come from here). Partial: most rows have no client MAC, and every
    // lens query shape implies source_client_mac IS NOT NULL.
    version: 4,
    sql: `
      CREATE INDEX idx_events_source_client_mac ON events(source_client_mac)
        WHERE source_client_mac IS NOT NULL;
    `,
  },
];

export function openDb(path: string, log?: (message: string) => void): Db {
  if (path !== ':memory:') {
    const dir = dirname(path);
    if (dir && dir !== '.') mkdirSync(dir, { recursive: true });
  }

  const conn = new DatabaseSync(path);
  // auto_vacuum must be set before any other pragma/statement that touches the database
  // header (e.g. journal_mode) writes it for the first time — after that, SQLite silently
  // ignores changes to auto_vacuum. See Finding 1 of the 2026-08-28 final review.
  conn.exec('PRAGMA auto_vacuum = INCREMENTAL;');
  conn.exec('PRAGMA journal_mode = WAL;');
  conn.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);');

  const applied = new Set(
    (conn.prepare('SELECT version FROM schema_migrations').all() as { version: number }[]).map(
      (row) => row.version
    )
  );

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    conn.exec('BEGIN');
    try {
      if (migration.sql) conn.exec(migration.sql);
      const message = migration.run?.(conn);
      conn.prepare('INSERT INTO schema_migrations (version) VALUES (?)').run(migration.version);
      conn.exec('COMMIT');
      if (message) log?.(message);
    } catch (err) {
      conn.exec('ROLLBACK');
      throw err;
    }
  }

  // Query planner stats. Without sqlite_stat1, SQLite can't tell that an index is selective
  // when another one competes (e.g. lens's distinct-MAC scan picks idx_events_source_ip and
  // walks every non-Security row). 0x10002 is SQLite's recommended form at connection open:
  // analyze every table that needs it, bounded by a temporary analysis_limit. Lens opens the
  // file read-only, but its planner reads the stats written here. purgeOldEvents refreshes them.
  conn.exec('PRAGMA optimize=0x10002;');

  return {
    conn,
    close: () => {
      if (conn.isOpen) conn.close();
    },
  };
}

export function insertEvent(db: Db, event: EventRow): number {
  const stmt = db.conn.prepare(`
    INSERT INTO events (
      received_at, event_time, category, subcategory, severity, name,
      source_ip, dest_ip, source_port, dest_port, protocol, action,
      signature, message, device_host, source_client_name, source_client_mac,
      dest_client_name, dest_client_mac, raw, parsed
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(
    event.received_at,
    event.event_time,
    event.category,
    event.subcategory,
    event.severity,
    event.name,
    event.source_ip,
    event.dest_ip,
    event.source_port,
    event.dest_port,
    event.protocol,
    event.action,
    event.signature,
    event.message,
    event.device_host,
    event.source_client_name,
    event.source_client_mac,
    event.dest_client_name,
    event.dest_client_mac,
    event.raw,
    event.parsed
  );
  return Number(result.lastInsertRowid);
}

export function purgeOldEvents(db: Db, retentionDays: number, now: Date = new Date()): number {
  const cutoff = new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const result = db.conn.prepare('DELETE FROM events WHERE received_at < ?').run(cutoff);
  db.conn.exec('PRAGMA incremental_vacuum(1000);');
  db.conn.exec('PRAGMA optimize;');
  return Number(result.changes);
}
