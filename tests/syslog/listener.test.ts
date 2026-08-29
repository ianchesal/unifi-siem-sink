import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import dgram from 'node:dgram';
import { openDb, type Db } from '../../src/storage/db.js';
import { startSyslogListener, type SyslogListener } from '../../src/syslog/listener.js';

let dir: string;
let db: Db;
let listener: SyslogListener;
const PORT = 31514;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'unifi-siem-sink-test-'));
  db = openDb(join(dir, 'events.db'));
  listener = await startSyslogListener(db, { port: PORT, bindAddress: '127.0.0.1', maxMessageBytes: 100 });
});

afterEach(async () => {
  await listener.close();
  db.close();
  await rm(dir, { recursive: true, force: true });
});

function sendUdp(message: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const client = dgram.createSocket('udp4');
    client.send(message, PORT, '127.0.0.1', (err) => {
      client.close();
      if (err) reject(err);
      else resolve();
    });
  });
}

function waitFor(predicate: () => boolean, timeoutMs = 2000): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      if (predicate()) return resolve();
      if (Date.now() - start > timeoutMs) return reject(new Error('timed out waiting for condition'));
      setTimeout(check, 20);
    };
    check();
  });
}

describe('startSyslogListener', () => {
  it('parses and stores a valid incoming message', async () => {
    await sendUdp('CEF:0|Ubiquiti|UniFi Network|9.3.33|1|Test|1|msg=hello');
    await waitFor(() => {
      const row = db.conn.prepare('SELECT COUNT(*) as count FROM events').get() as { count: number };
      return row.count === 1;
    });
    const row = db.conn.prepare('SELECT * FROM events').get() as { parsed: number };
    expect(row.parsed).toBe(1);
  });

  it('drops oversized messages without storing them', async () => {
    const oversized = 'x'.repeat(200);
    await sendUdp(oversized);
    await waitFor(() => listener.droppedCount() === 1);
    const row = db.conn.prepare('SELECT COUNT(*) as count FROM events').get() as { count: number };
    expect(row.count).toBe(0);
  });

  it('stores an unparsed row for malformed input rather than dropping it', async () => {
    await sendUdp('not a cef message at all');
    await waitFor(() => {
      const row = db.conn.prepare('SELECT COUNT(*) as count FROM events').get() as { count: number };
      return row.count === 1;
    });
    const row = db.conn.prepare('SELECT * FROM events').get() as { parsed: number };
    expect(row.parsed).toBe(0);
  });
});
