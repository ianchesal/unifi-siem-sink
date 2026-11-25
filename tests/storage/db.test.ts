import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb, insertEvent, purgeOldEvents, type Db } from '../../src/storage/db.js';
import { unparsedEvent } from '../../src/parser/normalize.js';

let dir: string;
let dbPath: string;
let db: Db;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'unifi-siem-sink-test-'));
  dbPath = join(dir, 'events.db');
  db = openDb(dbPath);
});

afterEach(async () => {
  db.close();
  await rm(dir, { recursive: true, force: true });
});

describe('openDb', () => {
  it('creates the events table', () => {
    const row = db.conn
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
      .get();
    expect(row).toBeDefined();
  });

  it('is idempotent across repeated opens', () => {
    db.close();
    expect(() => openDb(dbPath)).not.toThrow();
  });

  it('enables incremental auto_vacuum on a freshly-created database', () => {
    const row = db.conn.prepare('PRAGMA auto_vacuum').get() as { auto_vacuum: number };
    expect(row.auto_vacuum).toBe(2);
  });

  it('creates the parent directory of the db path if it does not exist', () => {
    const nestedPath = join(dir, 'nested', 'sub', 'events.db');
    const nestedDb = openDb(nestedPath);
    try {
      const row = nestedDb.conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        .get();
      expect(row).toBeDefined();
    } finally {
      nestedDb.close();
    }
  });
});

describe('insertEvent', () => {
  it('stores a row and returns its id', () => {
    const id = insertEvent(db, unparsedEvent('raw message', '2026-08-28T22:00:00.000Z'));
    expect(id).toBeGreaterThan(0);
    const row = db.conn.prepare('SELECT * FROM events WHERE id = ?').get(id) as { raw: string };
    expect(row.raw).toBe('raw message');
  });
});

describe('purgeOldEvents', () => {
  it('deletes rows older than the retention window and keeps newer ones', () => {
    insertEvent(db, unparsedEvent('old', '2026-01-01T00:00:00.000Z'));
    insertEvent(db, unparsedEvent('new', '2026-08-28T00:00:00.000Z'));
    const now = new Date('2026-08-28T12:00:00.000Z');

    const deleted = purgeOldEvents(db, 90, now);

    expect(deleted).toBe(1);
    const remaining = db.conn.prepare('SELECT raw FROM events').all() as { raw: string }[];
    expect(remaining.map((r) => r.raw)).toEqual(['new']);
  });
});

describe('client identity schema (migrations 2 and 3)', () => {
  const ORIGINAL_COLUMNS = [
    'id', 'received_at', 'event_time', 'category', 'subcategory', 'severity', 'name',
    'source_ip', 'dest_ip', 'source_port', 'dest_port', 'protocol', 'action', 'signature',
    'message', 'device_host', 'raw', 'parsed',
  ];
  const CLIENT_COLUMNS = ['source_client_name', 'source_client_mac', 'dest_client_name', 'dest_client_mac'];

  it('adds the four client columns and keeps the original 18', () => {
    const names = (db.conn.prepare('PRAGMA table_info(events)').all() as { name: string }[]).map(
      (r) => r.name
    );
    for (const col of [...ORIGINAL_COLUMNS, ...CLIENT_COLUMNS]) expect(names).toContain(col);
  });

  it('records migrations 1 through 4', () => {
    const versions = (
      db.conn.prepare('SELECT version FROM schema_migrations ORDER BY version').all() as {
        version: number;
      }[]
    ).map((r) => r.version);
    expect(versions).toEqual([1, 2, 3, 4]);
  });

  it('insertEvent persists client columns', () => {
    const id = insertEvent(db, {
      ...unparsedEvent('raw', '2026-11-25T00:00:00.000Z'),
      source_client_name: 'tranquility',
      source_client_mac: '1c:1b:0d:18:07:53',
      dest_client_name: 'nas',
      dest_client_mac: 'bb:bb:bb:bb:bb:bb',
    });
    const row = db.conn
      .prepare(`SELECT ${CLIENT_COLUMNS.join(', ')} FROM events WHERE id = ?`)
      .get(id) as Record<string, string>;
    expect(row).toEqual({
      source_client_name: 'tranquility',
      source_client_mac: '1c:1b:0d:18:07:53',
      dest_client_name: 'nas',
      dest_client_mac: 'bb:bb:bb:bb:bb:bb',
    });
  });

  it('logs the migration 3 summary through the optional logger', () => {
    db.close();
    const fresh = join(dir, 'fresh.db');
    const messages: string[] = [];
    const db2 = openDb(fresh, (m) => messages.push(m));
    db2.close();
    expect(messages.some((m) => m.startsWith('Migration 3:'))).toBe(true);
    db = openDb(dbPath);
  });
});

describe('source_client_mac index (migration 4)', () => {
  const plan = (sql: string, ...params: (string | null)[]) =>
    (db.conn.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...params) as { detail: string }[])
      .map((r) => r.detail)
      .join('\n');

  it('creates a partial index on source_client_mac', () => {
    const row = db.conn
      .prepare("SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_events_source_client_mac'")
      .get() as { sql: string } | undefined;
    expect(row?.sql).toMatch(/ON events\s*\(\s*source_client_mac\s*\)/i);
    expect(row?.sql).toMatch(/WHERE\s+source_client_mac IS NOT NULL/i);
  });

  // The three query shapes unifi-siem-lens runs against this column (issue #44).
  it('is used for the client-name lookup by MAC list', () => {
    expect(
      plan(
        `SELECT source_client_mac, MAX(received_at) FROM events
         WHERE source_client_mac IN (?, ?) AND source_client_name IS NOT NULL
         GROUP BY source_client_mac`,
        'aa:aa:aa:aa:aa:aa',
        'bb:bb:bb:bb:bb:bb'
      )
    ).toContain('idx_events_source_client_mac');
  });

  it('is used for events-by-MAC lookups', () => {
    expect(
      plan(
        'SELECT * FROM events WHERE source_client_mac = ? AND source_ip IS NULL ORDER BY received_at DESC',
        'aa:aa:aa:aa:aa:aa'
      )
    ).toContain('idx_events_source_client_mac');
  });

  // This one has two competing indexes (category, source_ip), so the planner only picks
  // the MAC index once it has sqlite_stat1 stats, which openDb gathers via PRAGMA optimize.
  it('is used for the distinct-MAC scan once the database has stats', () => {
    const ins = db.conn.prepare(
      "INSERT INTO events (received_at, category, source_ip, source_client_mac, raw, parsed) VALUES (?, ?, ?, ?, 'r', 1)"
    );
    db.conn.exec('BEGIN');
    for (let i = 0; i < 5000; i++) {
      const security = i % 4 === 0;
      const clientOnly = security && i % 40 === 0;
      ins.run(
        new Date(i * 1000).toISOString(),
        security ? 'threat' : 'system',
        security && !clientOnly ? '203.0.113.9' : null,
        clientOnly ? `aa:aa:aa:aa:aa:0${i % 7}` : null
      );
    }
    db.conn.exec('COMMIT');
    db.close();
    db = openDb(dbPath);

    expect(
      plan(
        `SELECT DISTINCT source_client_mac FROM events
         WHERE source_ip IS NULL AND source_client_mac IS NOT NULL AND category IN (?, ?)`,
        'threat',
        'ips'
      )
    ).toContain('idx_events_source_client_mac');
  });
});
