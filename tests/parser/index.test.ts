import { describe, it, expect } from 'vitest';
import { parseMessage } from '../../src/parser/index.js';

const ADMIN_LOGIN_RAW =
  '<134>Aug 28 22:00:00 UDM-Pro CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|UNIFIcategory=System UNIFIsubCategory=Admin src=105.5.138.59 msg=Craig accessed UniFi Network using the web.';

describe('parseMessage', () => {
  it('parses a well-formed enveloped CEF message end to end', () => {
    const row = parseMessage(ADMIN_LOGIN_RAW, '2026-08-28T22:00:00.000Z');
    expect(row.parsed).toBe(1);
    expect(row.category).toBe('admin_action');
    expect(row.source_ip).toBe('105.5.138.59');
    expect(row.raw).toBe(ADMIN_LOGIN_RAW);
    expect(row.received_at).toBe('2026-08-28T22:00:00.000Z');
  });

  it('defaults received_at to now when not provided', () => {
    const before = Date.now();
    const row = parseMessage(ADMIN_LOGIN_RAW);
    const after = Date.now();
    const receivedAtMs = new Date(row.received_at).getTime();
    expect(receivedAtMs).toBeGreaterThanOrEqual(before);
    expect(receivedAtMs).toBeLessThanOrEqual(after);
  });

  it('falls back to an unparsed row when there is no CEF marker', () => {
    const row = parseMessage('<134>Aug 28 22:00:00 UDM-Pro some unrelated log line');
    expect(row.parsed).toBe(0);
    expect(row.category).toBe('unknown');
    expect(row.raw).toBe('<134>Aug 28 22:00:00 UDM-Pro some unrelated log line');
  });

  it('falls back to an unparsed row for a truncated CEF header', () => {
    const row = parseMessage('CEF:0|Ubiquiti|UniFi Network');
    expect(row.parsed).toBe(0);
  });

  it('never throws for an empty string', () => {
    expect(() => parseMessage('')).not.toThrow();
    expect(parseMessage('').parsed).toBe(0);
  });

  it('never throws for garbage binary-ish input', () => {
    const garbage = ' CEF:garbage\\|\\|\\|no-real-fields';
    expect(() => parseMessage(garbage)).not.toThrow();
  });
});
