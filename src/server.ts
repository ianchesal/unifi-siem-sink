import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { type NextFunction, type Request, type Response } from 'express';
import type { Config } from './config.js';
import type { Db } from './storage/db.js';
import type { SyslogListener } from './syslog/listener.js';
import { registerAllTools } from './tools/index.js';

export function createApp(db: Db, config: Config, listener: SyslogListener) {
  const app = express();
  app.use(express.json());

  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const auth = req.headers.authorization;
    if (!auth || auth !== `Bearer ${config.mcpSecret}`) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', droppedMessages: listener.droppedCount() });
  });

  app.post('/mcp', authMiddleware, async (req, res, next) => {
    const mcpServer = new McpServer({ name: 'unifi-siem-sink', version: '0.1.0' });
    registerAllTools(mcpServer, db);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      transport.close();
      mcpServer.close();
    });
    try {
      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      next(err);
    }
  });

  return app;
}
