import { loadConfig } from './config.js';
import { createLogger } from './logger.js';
import { createApp } from './server.js';
import { openDb, purgeOldEvents } from './storage/db.js';
import { startSyslogListener } from './syslog/listener.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);

logger.info('Starting unifi-siem-sink');

const db = openDb(config.dbPath);

const purgeIntervalMs = 60 * 60 * 1000;
const purgeTimer = setInterval(() => {
  const deleted = purgeOldEvents(db, config.retentionDays);
  if (deleted > 0) logger.info(`Purged ${deleted} events older than ${config.retentionDays} days`);
}, purgeIntervalMs);

const listener = await startSyslogListener(db, {
  port: config.syslogUdpPort,
  bindAddress: config.syslogBindAddress,
  maxMessageBytes: config.maxMessageBytes,
});
logger.info(`Syslog UDP listener bound on ${config.syslogBindAddress}:${config.syslogUdpPort}`);

const app = createApp(db, config, listener);
const httpServer = app.listen(config.mcpPort, config.mcpHost, () => {
  logger.info(`MCP server listening on ${config.mcpHost}:${config.mcpPort}`);
  logger.info(
    `POST http://${config.mcpHost}:${config.mcpPort}/mcp  (requires Authorization: Bearer <MCP_SECRET>)`
  );
  logger.info(`GET  http://${config.mcpHost}:${config.mcpPort}/health`);
});

async function shutdown(signal: string): Promise<void> {
  logger.info(`Received ${signal}, shutting down`);
  clearInterval(purgeTimer);
  await listener.close();
  httpServer.close();
  db.close();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
