import type { LogLevel } from './logger.js';

export interface Config {
  syslogUdpPort: number;
  syslogBindAddress: string;
  mcpPort: number;
  mcpHost: string;
  mcpSecret: string;
  dbPath: string;
  retentionDays: number;
  maxMessageBytes: number;
  logLevel: LogLevel;
}

function parseIntEnv(key: string, defaultValue: number): number {
  const raw = process.env[key];
  if (!raw) return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${key} must be a number, got: "${raw}"`);
  }
  return parsed;
}

export function loadConfig(): Config {
  if (!process.env.MCP_SECRET?.trim()) {
    throw new Error('Missing required environment variable: MCP_SECRET');
  }

  const validLevels: LogLevel[] = ['error', 'warn', 'info', 'debug'];
  const rawLogLevel = process.env.LOG_LEVEL ?? 'info';
  if (!validLevels.includes(rawLogLevel as LogLevel)) {
    throw new Error(`LOG_LEVEL must be one of: ${validLevels.join(', ')}, got: "${rawLogLevel}"`);
  }

  return {
    syslogUdpPort: parseIntEnv('SYSLOG_UDP_PORT', 10514),
    syslogBindAddress: process.env.SYSLOG_BIND_ADDRESS ?? '0.0.0.0',
    mcpPort: parseIntEnv('MCP_PORT', 3000),
    mcpHost: process.env.MCP_HOST ?? '0.0.0.0',
    mcpSecret: process.env.MCP_SECRET,
    dbPath: process.env.DB_PATH ?? './data/events.db',
    retentionDays: parseIntEnv('RETENTION_DAYS', 90),
    maxMessageBytes: parseIntEnv('MAX_MESSAGE_BYTES', 16384),
    logLevel: rawLogLevel as LogLevel,
  };
}
