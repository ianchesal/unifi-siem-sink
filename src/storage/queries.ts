import type { EventRow } from '../parser/normalize.js';
import { ipInCidr } from './cidr.js';
import type { Db } from './db.js';

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

// A large-but-bounded cap applied when a CIDR filter's prefix length isn't a multiple of 8
// (e.g. /12, /20), so there's no clean SQL LIKE prefix to push down. This still bounds the
// worst-case row set materialized before the JS ipInCidr post-filter, even though it's coarser
// than the octet-aligned LIKE filter used below. See Finding 5 of the 2026-08-28 final review.
const CIDR_FALLBACK_LIMIT = 10000;

/**
 * For a CIDR whose prefix length is a multiple of 8 (/8, /16, /24, /32), derive a coarse
 * SQL-level filter clause that is a superset of the true CIDR match: an exact match for /32,
 * or a `LIKE 'a.b.c.%'`-style prefix match otherwise. Returns null if the prefix isn't
 * octet-aligned (no clean SQL equivalent) or the CIDR is malformed.
 */
function cidrSqlClause(column: string, cidr: string): { clause: string; param: string } | null {
  const [rangeIp, prefixStr] = cidr.split('/');
  if (!rangeIp || prefixStr === undefined) return null;
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix % 8 !== 0 || prefix === 0) return null;

  const octets = rangeIp.split('.');
  if (octets.length !== 4) return null;

  const keepOctets = prefix / 8;
  if (keepOctets === 4) {
    return { clause: `${column} = ?`, param: rangeIp };
  }
  const prefixOctets = octets.slice(0, keepOctets).join('.');
  return { clause: `${column} LIKE ?`, param: `${prefixOctets}.%` };
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

  const sourceCidr = filters.sourceIp && isCidr(filters.sourceIp) ? filters.sourceIp : undefined;
  const destCidr = filters.destIp && isCidr(filters.destIp) ? filters.destIp : undefined;
  const hasCidrFilter = sourceCidr !== undefined || destCidr !== undefined;

  if (hasCidrFilter) {
    // CIDR containment can't be expressed exactly in SQL, so we can't apply LIMIT/OFFSET or
    // COUNT(*) at the SQL level without over/under-counting. To avoid materializing every row
    // matching the non-CIDR clauses, we push down a coarse octet-aligned prefix filter (LIKE or
    // exact match) for CIDRs whose prefix length is a multiple of 8 — this is a superset of the
    // true match, refined below by the JS ipInCidr filter. For non-octet-aligned prefixes (no
    // clean SQL equivalent), we fall back to a large-but-bounded SQL LIMIT instead.
    const cidrClauses: string[] = [];
    const cidrParams: (string | number)[] = [];
    let usedFallbackLimit = false;

    if (sourceCidr) {
      const sql = cidrSqlClause('source_ip', sourceCidr);
      if (sql) {
        cidrClauses.push(sql.clause);
        cidrParams.push(sql.param);
      } else {
        usedFallbackLimit = true;
      }
    }
    if (destCidr) {
      const sql = cidrSqlClause('dest_ip', destCidr);
      if (sql) {
        cidrClauses.push(sql.clause);
        cidrParams.push(sql.param);
      } else {
        usedFallbackLimit = true;
      }
    }

    const allClauses = [...clauses, ...cidrClauses];
    const cidrWhere = allClauses.length > 0 ? `WHERE ${allClauses.join(' AND ')}` : '';
    const allParams = [...params, ...cidrParams];

    const boundedSql = usedFallbackLimit
      ? `SELECT * FROM events ${cidrWhere} ORDER BY received_at DESC LIMIT ${CIDR_FALLBACK_LIMIT}`
      : `SELECT * FROM events ${cidrWhere} ORDER BY received_at DESC`;

    let rows = db.conn.prepare(boundedSql).all(...allParams) as unknown as StoredEvent[];

    if (sourceCidr) {
      rows = rows.filter((row) => row.source_ip !== null && ipInCidr(row.source_ip, sourceCidr));
    }
    if (destCidr) {
      rows = rows.filter((row) => row.dest_ip !== null && ipInCidr(row.dest_ip, destCidr));
    }

    const total = rows.length;
    const events = rows.slice(offset, offset + limit);
    return { events, total };
  }

  const rows = db.conn
    .prepare(`SELECT * FROM events ${where} ORDER BY received_at DESC LIMIT ? OFFSET ?`)
    .all(...params, limit, offset) as unknown as StoredEvent[];

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
  const rows = db.conn.prepare('SELECT DISTINCT category FROM events ORDER BY category').all() as {
    category: string;
  }[];
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
