import type { DatabaseSync } from 'node:sqlite';
import { parseMessage } from '../parser/index.js';

// The columns the 2026-11-25 gateway-misattribution fix changed the derivation of.
const OWNED_COLUMNS = [
  'source_ip',
  'dest_ip',
  'source_client_name',
  'source_client_mac',
  'dest_client_name',
  'dest_client_mac',
] as const;

type OwnedColumn = (typeof OWNED_COLUMNS)[number];
type CandidateRow = { id: number; raw: string; received_at: string } & Record<
  OwnedColumn,
  string | null
>;

export interface ReparseResult {
  updated: number;
  sourceIpChanged: number;
}

// Re-derives source/dest IP and client identity for rows written before Security events stopped
// falling back to UNIFIdeviceIp. The LIKE selection is deliberately a superset (e.g.
// `UNIFIdeviceIp=192.168.1.1` also matches `…1.10`, and `_` is a LIKE wildcard): the re-parse is
// authoritative, and only rows whose owned columns actually differ are written.
export function reparseClientEvents(conn: DatabaseSync): ReparseResult {
  const candidates = conn
    .prepare(
      `SELECT id, raw, received_at, ${OWNED_COLUMNS.join(', ')}
       FROM events
       WHERE raw LIKE '%UNIFIsrcClient%'
          OR raw LIKE '%UNIFIdstClient%'
          OR (source_ip IS NOT NULL
              AND raw LIKE '%UNIFIcategory=Security%'
              AND raw LIKE '%UNIFIdeviceIp=' || source_ip || '%')`
    )
    .all() as CandidateRow[];

  const update = conn.prepare(
    `UPDATE events SET ${OWNED_COLUMNS.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`
  );

  const result: ReparseResult = { updated: 0, sourceIpChanged: 0 };
  for (const row of candidates) {
    const reparsed = parseMessage(row.raw, row.received_at);
    // Never overwrite stored values with the all-null output of a failed parse.
    if (reparsed.parsed === 0) continue;
    if (OWNED_COLUMNS.every((c) => reparsed[c] === row[c])) continue;
    update.run(...OWNED_COLUMNS.map((c) => reparsed[c]), row.id);
    result.updated++;
    if (reparsed.source_ip !== row.source_ip) result.sourceIpChanged++;
  }
  return result;
}
