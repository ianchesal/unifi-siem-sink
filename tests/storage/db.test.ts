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
