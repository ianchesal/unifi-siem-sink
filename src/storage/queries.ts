import type { Db } from './db.js';
import { ipInCidr } from './cidr.js';
import type { EventRow } from '../parser/normalize.js';

export interface StoredEvent extends EventRow {
  id: number;
}

export interface ListEventsFilters {
  since?: string;
  until?: string;
  category?: string;
  severityMin?: number;
  sourceIp?: string;
  destIp?: string;
  limit?: number;
  offset?: number;
}

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

function isCidr(value: string): boolean {
  return value.includes('/');
}

export function listEvents(
  db: Db,
  filters: ListEventsFilters = {}
): { events: StoredEvent[]; total: number } {
  const clauses: string[] = [];
  const params: (string | number)[] = [];

  if (filters.since) {
    clauses.push('received_at >= ?');
    params.push(filters.since);
  }
  if (filters.until) {
    clauses.push('received_at <= ?');
    params.push(filters.until);
  }
  if (filters.category) {
    clauses.push('category = ?');
    params.push(filters.category);
  }
  if (filters.severityMin !== undefined) {
    clauses.push('severity >= ?');
    params.push(filters.severityMin);
  }
  if (filters.sourceIp && !isCidr(filters.sourceIp)) {
    clauses.push('source_ip = ?');
    params.push(filters.sourceIp);
  }
  if (filters.destIp && !isCidr(filters.destIp)) {
    clauses.push('dest_ip = ?');
    params.push(filters.destIp);
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const limit = Math.min(filters.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
  const offset = filters.offset ?? 0;

  let rows = db.conn
    .prepare(`SELECT * FROM events ${where} ORDER BY received_at DESC LIMIT ? OFFSET ?`)
    .all(...params, limit, offset) as unknown as StoredEvent[];

  if (filters.sourceIp && isCidr(filters.sourceIp)) {
    const cidr = filters.sourceIp;
    rows = rows.filter((row) => row.source_ip !== null && ipInCidr(row.source_ip, cidr));
  }
  if (filters.destIp && isCidr(filters.destIp)) {
    const cidr = filters.destIp;
    rows = rows.filter((row) => row.dest_ip !== null && ipInCidr(row.dest_ip, cidr));
  }

  const totalRow = db.conn
    .prepare(`SELECT COUNT(*) as count FROM events ${where}`)
    .get(...params) as { count: number };

  return { events: rows, total: totalRow.count };
}

export function getEvent(db: Db, id: number): StoredEvent | null {
  const row = db.conn.prepare('SELECT * FROM events WHERE id = ?').get(id) as
    | StoredEvent
    | undefined;
  return row ?? null;
}

export function getCategories(db: Db): string[] {
  const rows = db.conn
    .prepare('SELECT DISTINCT category FROM events ORDER BY category')
    .all() as { category: string }[];
  return rows.map((r) => r.category);
}

export interface EventStatsFilters {
  since?: string;
  until?: string;
  groupBy: 'category' | 'severity' | 'source_ip';
}

const GROUP_BY_COLUMNS = {
  category: 'category',
  severity: 'severity',
  source_ip: 'source_ip',
} as const;

export function getEventStats(
  db: Db,
  filters: EventStatsFilters
): { key: string; count: number }[] {
  const clauses: string[] = [];
  const params: (string | number)[] = [];
  if (filters.since) {
    clauses.push('received_at >= ?');
    params.push(filters.since);
  }
  if (filters.until) {
    clauses.push('received_at <= ?');
    params.push(filters.until);
  }
  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const column = GROUP_BY_COLUMNS[filters.groupBy];

  const rows = db.conn
    .prepare(
      `SELECT ${column} as key, COUNT(*) as count FROM events ${where} GROUP BY ${column} ORDER BY count DESC`
    )
    .all(...params) as { key: string | number | null; count: number }[];

  return rows.map((r) => ({ key: r.key === null ? 'unknown' : String(r.key), count: r.count }));
}
