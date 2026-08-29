import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb, insertEvent, type Db } from '../../src/storage/db.js';
import { unparsedEvent } from '../../src/parser/normalize.js';
import {
  listEventsTool,
  getEventTool,
  getCategoriesTool,
  getEventStatsTool,
} from '../../src/tools/events.js';

let dir: string;
let db: Db;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'unifi-siem-sink-test-'));
  db = openDb(join(dir, 'events.db'));
  insertEvent(db, unparsedEvent('event-1', '2026-08-28T10:00:00.000Z'));
});

afterEach(async () => {
  db.close();
  await rm(dir, { recursive: true, force: true });
});

describe('listEventsTool', () => {
  it('returns events and total', async () => {
    const result = await listEventsTool(db, {});
    expect(result.total).toBe(1);
    expect(result.events[0].raw).toBe('event-1');
  });
});

describe('getEventTool', () => {
  it('returns the event by id', async () => {
    const { events } = await listEventsTool(db, {});
    const found = await getEventTool(db, { id: events[0].id });
    expect(found.raw).toBe('event-1');
  });

  it('throws for a missing id', async () => {
    await expect(getEventTool(db, { id: 999999 })).rejects.toThrow(/not found/i);
  });
});

describe('getCategoriesTool', () => {
  it('returns distinct categories', async () => {
    const result = await getCategoriesTool(db);
    expect(result.categories).toEqual(['unknown']);
  });
});

describe('getEventStatsTool', () => {
  it('returns grouped counts', async () => {
    const result = await getEventStatsTool(db, { groupBy: 'category' });
    expect(result.groups).toEqual([{ key: 'unknown', count: 1 }]);
  });
});
