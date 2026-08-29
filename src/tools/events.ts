import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Db } from '../storage/db.js';
import {
  type EventStatsFilters,
  getCategories,
  getEvent,
  getEventStats,
  type ListEventsFilters,
  listEvents,
  type StoredEvent,
} from '../storage/queries.js';
import { toolError, toolResult } from './util.js';

export async function listEventsTool(db: Db, params: ListEventsFilters) {
  return listEvents(db, params);
}

export async function getEventTool(db: Db, params: { id: number }): Promise<StoredEvent> {
  const event = getEvent(db, params.id);
  if (!event) {
    throw new Error(`Event ${params.id} not found`);
  }
  return event;
}

export async function getCategoriesTool(db: Db): Promise<{ categories: string[] }> {
  return { categories: getCategories(db) };
}

export async function getEventStatsTool(db: Db, params: EventStatsFilters) {
  return { groups: getEventStats(db, params) };
}

export function registerEventTools(server: McpServer, db: Db): void {
  server.tool(
    'list_events',
    'List stored UniFi SIEM events. Filters: since/until (ISO8601 timestamps, filtered on receipt time), category, severity_min, source_ip/dest_ip (exact match or CIDR, e.g. "10.0.30.0/24"), limit (default 100, max 500), offset.',
    {
      since: z.string().optional(),
      until: z.string().optional(),
      category: z.string().optional(),
      severity_min: z.number().int().min(0).max(10).optional(),
      source_ip: z.string().optional(),
      dest_ip: z.string().optional(),
      limit: z.number().int().min(1).max(500).optional(),
      offset: z.number().int().min(0).optional(),
    },
    async (p) => {
      try {
        const result = await listEventsTool(db, {
          since: p.since,
          until: p.until,
          category: p.category,
          severityMin: p.severity_min,
          sourceIp: p.source_ip,
          destIp: p.dest_ip,
          limit: p.limit,
          offset: p.offset,
        });
        return toolResult(result);
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'get_event',
    'Get a single stored event by id, including its full raw syslog message.',
    { id: z.number().int() },
    async (p) => {
      try {
        return toolResult(await getEventTool(db, p));
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'get_categories',
    'List the distinct event categories currently present in the store (e.g. "ips_alert", "firewall_block", "honeypot", "admin_action", "unknown").',
    {},
    async () => {
      try {
        return toolResult(await getCategoriesTool(db));
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'get_event_stats',
    'Get aggregate event counts grouped by category, severity, or source_ip, optionally within a time range (since/until, ISO8601).',
    {
      since: z.string().optional(),
      until: z.string().optional(),
      group_by: z.enum(['category', 'severity', 'source_ip']),
    },
    async (p) => {
      try {
        const result = await getEventStatsTool(db, {
          since: p.since,
          until: p.until,
          groupBy: p.group_by,
        });
        return toolResult(result);
      } catch (e) {
        return toolError(e);
      }
    }
  );
}
