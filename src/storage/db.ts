import { DatabaseSync } from 'node:sqlite';
import type { EventRow } from '../parser/normalize.js';

export interface Db {
  conn: DatabaseSync;
  close(): void;
}

const MIGRATIONS: { version: number; sql: string }[] = [
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
];

export function openDb(path: string): Db {
  const conn = new DatabaseSync(path);
  conn.exec('PRAGMA journal_mode = WAL;');
  conn.exec('PRAGMA auto_vacuum = INCREMENTAL;');
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
      conn.exec(migration.sql);
      conn.prepare('INSERT INTO schema_migrations (version) VALUES (?)').run(migration.version);
      conn.exec('COMMIT');
    } catch (err) {
      conn.exec('ROLLBACK');
      throw err;
    }
  }

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
      signature, message, device_host, raw, parsed
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    event.raw,
    event.parsed
  );
  return Number(result.lastInsertRowid);
}

export function purgeOldEvents(db: Db, retentionDays: number, now: Date = new Date()): number {
  const cutoff = new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const result = db.conn.prepare('DELETE FROM events WHERE received_at < ?').run(cutoff);
  db.conn.exec('PRAGMA incremental_vacuum(1000);');
  return Number(result.changes);
}
