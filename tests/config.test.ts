import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../src/config.js';

const ENV_KEYS = [
  'MCP_SECRET',
  'SYSLOG_UDP_PORT',
  'SYSLOG_BIND_ADDRESS',
  'MCP_PORT',
  'MCP_HOST',
  'DB_PATH',
  'RETENTION_DAYS',
  'MAX_MESSAGE_BYTES',
  'LOG_LEVEL',
];
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

describe('loadConfig', () => {
  it('throws when MCP_SECRET is missing', () => {
    expect(() => loadConfig()).toThrow(/MCP_SECRET/);
  });

  it('applies defaults when only MCP_SECRET is set', () => {
    process.env.MCP_SECRET = 'test-secret';
    const config = loadConfig();
    expect(config).toEqual({
      syslogUdpPort: 10514,
      syslogBindAddress: '0.0.0.0',
      mcpPort: 3000,
      mcpHost: '0.0.0.0',
      mcpSecret: 'test-secret',
      dbPath: './data/events.db',
      retentionDays: 90,
      maxMessageBytes: 16384,
      logLevel: 'info',
    });
  });

  it('reads overrides from the environment', () => {
    process.env.MCP_SECRET = 'test-secret';
    process.env.SYSLOG_UDP_PORT = '514';
    process.env.RETENTION_DAYS = '30';
    process.env.LOG_LEVEL = 'debug';
    const config = loadConfig();
    expect(config.syslogUdpPort).toBe(514);
    expect(config.retentionDays).toBe(30);
    expect(config.logLevel).toBe('debug');
  });

  it('throws on a non-numeric numeric field', () => {
    process.env.MCP_SECRET = 'test-secret';
    process.env.SYSLOG_UDP_PORT = 'not-a-number';
    expect(() => loadConfig()).toThrow(/SYSLOG_UDP_PORT/);
  });

  it('throws on an invalid LOG_LEVEL', () => {
    process.env.MCP_SECRET = 'test-secret';
    process.env.LOG_LEVEL = 'verbose';
    expect(() => loadConfig()).toThrow(/LOG_LEVEL/);
  });
});
