import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { openDb, type Db } from '../src/storage/db.js';
import { createApp } from '../src/server.js';
import type { Config } from '../src/config.js';
import type { SyslogListener } from '../src/syslog/listener.js';

let dir: string;
let db: Db;

const config: Config = {
  syslogUdpPort: 10514,
  syslogBindAddress: '0.0.0.0',
  mcpPort: 3000,
  mcpHost: '0.0.0.0',
  mcpSecret: 'test-secret',
  dbPath: ':memory:',
  retentionDays: 90,
  maxMessageBytes: 16384,
  logLevel: 'error',
};

function makeListener(dropped = 0): SyslogListener {
  return { droppedCount: () => dropped, close: async () => {} };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'unifi-siem-sink-test-'));
  db = openDb(join(dir, 'events.db'));
});

afterEach(async () => {
  db.close();
  await rm(dir, { recursive: true, force: true });
});

describe('GET /health', () => {
  it('returns 200 without auth and reports the dropped-message count', async () => {
    const app = createApp(db, config, makeListener(3));
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.droppedMessages).toBe(3);
  });
});

describe('POST /mcp', () => {
  it('rejects requests without a Bearer token', async () => {
    const app = createApp(db, config, makeListener());
    const res = await request(app).post('/mcp').send({});
    expect(res.status).toBe(401);
  });

  it('rejects requests with the wrong Bearer token', async () => {
    const app = createApp(db, config, makeListener());
    const res = await request(app).post('/mcp').set('Authorization', 'Bearer wrong').send({});
    expect(res.status).toBe(401);
  });
});
