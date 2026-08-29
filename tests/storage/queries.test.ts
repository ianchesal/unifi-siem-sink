// tests/storage/queries.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb, insertEvent, type Db } from '../../src/storage/db.js';
import { listEvents, getEvent, getCategories, getEventStats } from '../../src/storage/queries.js';
import { unparsedEvent, normalize } from '../../src/parser/normalize.js';
import type { CefMessage } from '../../src/parser/cef.js';

let dir: string;
let db: Db;

function makeCef(overrides: Partial<CefMessage> = {}): CefMessage {
  return {
    version: '0', vendor: 'Ubiquiti', product: 'UniFi Network', deviceVersion: '9.3.33',
    signatureId: '1', name: 'Test', severity: '5', extension: {}, ...overrides,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'unifi-siem-sink-test-'));
  db = openDb(join(dir, 'events.db'));

  insertEvent(db, normalize(
    makeCef({ extension: { UNIFIcategory: 'Security', UNIFIsubCategory: 'Intrusion Prevention', src: '10.0.30.5' } }),
    'ips-1', '2026-08-28T10:00:00.000Z'
  ));
  insertEvent(db, normalize(
    makeCef({ extension: { UNIFIcategory: 'Security', UNIFIsubCategory: 'Firewall', src: '10.0.31.9' } }),
    'fw-1', '2026-08-28T11:00:00.000Z'
  ));
  insertEvent(db, unparsedEvent('unparsed-1', '2026-08-28T12:00:00.000Z'));
});

afterEach(async () => {
  db.close();
  await rm(dir, { recursive: true, force: true });
});

describe('listEvents', () => {
  it('returns all events with no filters, newest first', () => {
    const { events, total } = listEvents(db);
    expect(total).toBe(3);
    expect(events[0].raw).toBe('unparsed-1');
  });

  it('filters by category', () => {
    const { events, total } = listEvents(db, { category: 'ips_alert' });
    expect(total).toBe(1);
    expect(events[0].raw).toBe('ips-1');
  });

  it('filters by exact source_ip', () => {
    const { events } = listEvents(db, { sourceIp: '10.0.30.5' });
    expect(events.map((e) => e.raw)).toEqual(['ips-1']);
  });

  it('filters by source_ip CIDR', () => {
    const { events } = listEvents(db, { sourceIp: '10.0.30.0/24' });
    expect(events.map((e) => e.raw)).toEqual(['ips-1']);
  });

  it('filters by time range on received_at', () => {
    const { events } = listEvents(db, { since: '2026-08-28T10:30:00.000Z', until: '2026-08-28T11:30:00.000Z' });
    expect(events.map((e) => e.raw)).toEqual(['fw-1']);
  });

  it('caps limit at 500 even when a larger value is requested', () => {
    const { events } = listEvents(db, { limit: 10000 });
    expect(events.length).toBeLessThanOrEqual(500);
  });

  it('computes total from CIDR-matched rows only, not from all rows matching the other filters', () => {
    // Add more CIDR-matching rows, plus a non-CIDR-matching row, to the 3 seeded in beforeEach.
    for (let i = 0; i < 4; i++) {
      insertEvent(
        db,
        normalize(
          makeCef({
            extension: {
              UNIFIcategory: 'Security',
              UNIFIsubCategory: 'Intrusion Prevention',
              src: `10.0.30.${20 + i}`,
            },
          }),
          `cidr-extra-${i}`,
          `2026-08-28T13:0${i}:00.000Z`
        )
      );
    }
    insertEvent(
      db,
      normalize(
        makeCef({
          extension: { UNIFIcategory: 'Security', UNIFIsubCategory: 'Firewall', src: '10.0.99.1' },
        }),
        'cidr-noncidr',
        '2026-08-28T13:10:00.000Z'
      )
    );

    // 5 rows total fall inside 10.0.30.0/24: the original ips-1 (10.0.30.5) plus the 4 extras.
    // The 6th inserted row (10.0.99.1) and the other seeded rows (10.0.31.9, no ip) do not match.
    const { events, total } = listEvents(db, { sourceIp: '10.0.30.0/24' });
    expect(total).toBe(5);
    expect(events.length).toBe(5);
  });

  it('paginates correctly (limit/offset) against the CIDR-filtered set, not the unfiltered set', () => {
    for (let i = 0; i < 4; i++) {
      insertEvent(
        db,
        normalize(
          makeCef({
            extension: {
              UNIFIcategory: 'Security',
              UNIFIsubCategory: 'Intrusion Prevention',
              src: `10.0.30.${20 + i}`,
            },
          }),
          `cidr-extra-${i}`,
          `2026-08-28T13:0${i}:00.000Z`
        )
      );
    }
    insertEvent(
      db,
      normalize(
        makeCef({
          extension: { UNIFIcategory: 'Security', UNIFIsubCategory: 'Firewall', src: '10.0.99.1' },
        }),
        'cidr-noncidr',
        '2026-08-28T13:10:00.000Z'
      )
    );

    const all = listEvents(db, { sourceIp: '10.0.30.0/24' });
    expect(all.total).toBe(5);

    const page = listEvents(db, { sourceIp: '10.0.30.0/24', limit: 2, offset: 1 });
    expect(page.total).toBe(5);
    expect(page.events.length).toBe(2);
    expect(page.events.map((e) => e.raw)).toEqual(all.events.slice(1, 3).map((e) => e.raw));
  });
});

describe('getEvent', () => {
  it('returns the event by id', () => {
    const { events } = listEvents(db, { category: 'ips_alert' });
    const found = getEvent(db, events[0].id);
    expect(found?.raw).toBe('ips-1');
  });

  it('returns null for a missing id', () => {
    expect(getEvent(db, 999999)).toBeNull();
  });
});

describe('getCategories', () => {
  it('returns distinct categories present in the store', () => {
    expect(getCategories(db).sort()).toEqual(['firewall_block', 'ips_alert', 'unknown']);
  });
});

describe('getEventStats', () => {
  it('groups by category', () => {
    const stats = getEventStats(db, { groupBy: 'category' });
    const byKey = Object.fromEntries(stats.map((s) => [s.key, s.count]));
    expect(byKey.ips_alert).toBe(1);
    expect(byKey.firewall_block).toBe(1);
    expect(byKey.unknown).toBe(1);
  });
});
