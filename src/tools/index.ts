import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Db } from '../storage/db.js';
import { registerEventTools } from './events.js';

export function registerAllTools(server: McpServer, db: Db): void {
  registerEventTools(server, db);
}
