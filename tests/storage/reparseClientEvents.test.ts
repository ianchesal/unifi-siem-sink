import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb, type Db } from '../../src/storage/db.js';
import { reparseClientEvents } from '../../src/storage/reparseClientEvents.js';
import {
  RAW_INTERNET_DOWN_20260829,
  RAW_IPS_DST_ONLY_7521,
  RAW_IPS_SAME_CLIENT_7557,
} from '../fixtures/realSamples.js';

let dir: string;
let db: Db;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'unifi-siem-sink-reparse-'));
  db = openDb(join(dir, 'events.db'));
});

afterEach(async () => {
  db.close();
  await rm(dir, { recursive: true, force: true });
});

// Simulates a row written by the pre-fix code: client columns null.
function insertOld(row: {
  raw: string;
  category: string;
  source_ip: string | null;
  dest_ip?: string | null;
  signature?: string | null;
  parsed?: 0 | 1;
}): number {
  const result = db.conn
    .prepare(
      `INSERT INTO events (received_at, category, source_ip, dest_ip, signature, raw, parsed)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      '2026-11-25T15:16:13.735Z',
      row.category,
      row.source_ip,
      row.dest_ip ?? null,
      row.signature ?? null,
      row.raw,
      row.parsed ?? 1
    );
  return Number(result.lastInsertRowid);
}

function get(id: number): Record<string, unknown> {
  return db.conn.prepare('SELECT * FROM events WHERE id = ?').get(id) as Record<string, unknown>;
}

describe('reparseClientEvents', () => {
  it('repairs an IPS row stored on the gateway', () => {
    const id = insertOld({ raw: RAW_IPS_SAME_CLIENT_7557, category: 'ips_alert', source_ip: '192.168.1.1' });
    expect(reparseClientEvents(db.conn)).toEqual({ updated: 1, sourceIpChanged: 1 });
    const row = get(id);
    expect(row.source_ip).toBeNull();
    expect(row.dest_ip).toBeNull();
    expect(row.source_client_name).toBe('tranquility');
    expect(row.source_client_mac).toBe('1c:1b:0d:18:07:53');
    expect(row.dest_client_name).toBeNull();
  });

  it('fills client columns on a row whose source_ip is already right', () => {
    // Stored as if source_ip had been correct; only client columns are missing.
    const id = insertOld({
      raw: RAW_IPS_DST_ONLY_7521,
      category: 'ips_alert',
      source_ip: null,
      dest_ip: '140.82.112.3',
    });
    expect(reparseClientEvents(db.conn)).toEqual({ updated: 1, sourceIpChanged: 0 });
    expect(get(id).source_client_mac).toBe('d0:c1:b5:24:8e:54');
  });

  it('leaves internet_and_wan rows on the gateway untouched', () => {
    const id = insertOld({ raw: RAW_INTERNET_DOWN_20260829, category: 'internet_and_wan', source_ip: '192.168.1.1' });
    const before = get(id);
    expect(reparseClientEvents(db.conn)).toEqual({ updated: 0, sourceIpChanged: 0 });
    expect(get(id)).toEqual(before);
  });

  it('skips rows whose re-parse is unparsed', () => {
    const id = insertOld({
      raw: 'garbage UNIFIsrcClientMac=aa:bb UNIFIcategory=Security',
      category: 'unknown',
      source_ip: '10.0.0.9',
      parsed: 0,
    });
    expect(reparseClientEvents(db.conn)).toEqual({ updated: 0, sourceIpChanged: 0 });
    expect(get(id).source_ip).toBe('10.0.0.9');
  });

  it('second run reports zero changes', () => {
    insertOld({ raw: RAW_IPS_SAME_CLIENT_7557, category: 'ips_alert', source_ip: '192.168.1.1' });
    insertOld({ raw: RAW_IPS_DST_ONLY_7521, category: 'ips_alert', source_ip: '192.168.1.1', dest_ip: '140.82.112.3' });
    expect(reparseClientEvents(db.conn)).toEqual({ updated: 2, sourceIpChanged: 2 });
    expect(reparseClientEvents(db.conn)).toEqual({ updated: 0, sourceIpChanged: 0 });
  });

  it('leaves columns outside the six it owns alone', () => {
    const id = insertOld({
      raw: RAW_IPS_SAME_CLIENT_7557,
      category: 'ips_alert',
      source_ip: '192.168.1.1',
      signature: 'stored-signature',
    });
    const before = get(id);
    reparseClientEvents(db.conn);
    const after = get(id);
    for (const col of ['id', 'received_at', 'category', 'signature', 'raw', 'parsed', 'event_time', 'severity']) {
      expect(after[col]).toEqual(before[col]);
    }
  });
});

describe('migration 3 via openDb', () => {
  it('repairs bad rows when an existing database is upgraded', () => {
    const path = join(dir, 'upgrade.db');
    const old = openDb(path);
    old.conn.exec('DELETE FROM schema_migrations WHERE version = 3');
    const id = Number(
      old.conn
        .prepare(`INSERT INTO events (received_at, category, source_ip, raw, parsed) VALUES (?, 'ips_alert', '192.168.1.1', ?, 1)`)
        .run('2026-11-25T15:16:13.735Z', RAW_IPS_SAME_CLIENT_7557).lastInsertRowid
    );
    old.close();

    const messages: string[] = [];
    const upgraded = openDb(path, (m) => messages.push(m));
    const row = upgraded.conn.prepare('SELECT source_ip, source_client_name FROM events WHERE id = ?').get(id);
    upgraded.close();
    expect(row).toEqual({ source_ip: null, source_client_name: 'tranquility' });
    expect(messages).toEqual(['Migration 3: re-parsed client events: 1 rows updated, 1 source_ip corrected']);
  });
});
