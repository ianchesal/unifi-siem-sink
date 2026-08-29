import { stripEnvelope } from './envelope.js';
import { parseCef } from './cef.js';
import { normalize, unparsedEvent, type EventRow } from './normalize.js';

export type { EventRow } from './normalize.js';

export function parseMessage(raw: string, receivedAt: string = new Date().toISOString()): EventRow {
  try {
    const payload = stripEnvelope(raw);
    if (!payload) return unparsedEvent(raw, receivedAt);
    const cef = parseCef(payload);
    if (!cef) return unparsedEvent(raw, receivedAt);
    return normalize(cef, raw, receivedAt);
  } catch {
    return unparsedEvent(raw, receivedAt);
  }
}
