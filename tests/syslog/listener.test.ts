import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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

  it('does not crash the process when insertEvent throws (e.g. a closed db)', async () => {
    let caught: unknown = null;
    const onUncaught = (err: unknown) => {
      caught = err;
    };
    process.on('uncaughtException', onUncaught);
    try {
      // Close the db underlying this listener so insertEvent throws
      // synchronously when the next message arrives.
      db.close();
      await sendUdp('CEF:0|Ubiquiti|UniFi Network|9.3.33|1|Test|1|msg=hello');
      // Give the event loop a moment to deliver the datagram and run
      // (and fail) the insert attempt.
      await new Promise((resolve) => setTimeout(resolve, 200));
    } finally {
      process.removeListener('uncaughtException', onUncaught);
    }
    expect(caught).toBeNull();
  });

  it('does not crash the process on a runtime socket error', async () => {
    const createSocketSpy = vi.spyOn(dgram, 'createSocket');
    const otherDb = await (async () => {
      const otherDir = await mkdtemp(join(tmpdir(), 'unifi-siem-sink-test-'));
      return { dir: otherDir, db: openDb(join(otherDir, 'events.db')) };
    })();
    const otherListener = await startSyslogListener(otherDb.db, {
      port: PORT + 1,
      bindAddress: '127.0.0.1',
      maxMessageBytes: 100,
    });
    const socket = createSocketSpy.mock.results[createSocketSpy.mock.results.length - 1]
      .value as dgram.Socket;
    createSocketSpy.mockRestore();

    let caught: unknown = null;
    const onUncaught = (err: unknown) => {
      caught = err;
    };
    process.on('uncaughtException', onUncaught);
    try {
      // Simulate a runtime socket error (e.g. ECONNRESET from an ICMP
      // port-unreachable). With zero error listeners registered after
      // bind, this would be an unhandled 'error' event and crash the
      // process synchronously.
      socket.emit('error', new Error('simulated runtime socket error'));
    } finally {
      process.removeListener('uncaughtException', onUncaught);
    }
    expect(caught).toBeNull();

    await otherListener.close();
    otherDb.db.close();
    await rm(otherDb.dir, { recursive: true, force: true });
  });
});
