import { describe, it, expect } from 'vitest';
import { parseMessage } from '../../src/parser/index.js';
import {
  RAW_IPS_DST_ONLY_7521,
  RAW_IPS_SAME_CLIENT_7557,
  RAW_SECURITY_20260826,
} from '../fixtures/realSamples.js';

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

describe('parseMessage: real Security samples without src=', () => {
  it('7557 (both ends labeled the same client) is not attributed to the gateway', () => {
    const row = parseMessage(RAW_IPS_SAME_CLIENT_7557, '2026-11-25T15:16:13.735Z');
    expect(row.category).toBe('ips_alert');
    expect(row.source_ip).toBeNull();
    expect(row.dest_ip).toBeNull();
    expect(row.source_client_name).toBe('tranquility');
    expect(row.source_client_mac).toBe('1c:1b:0d:18:07:53');
    expect(row.dest_client_name).toBeNull();
    expect(row.dest_client_mac).toBeNull();
    expect(row.source_port).toBe(50330);
    expect(row.dest_port).toBe(52128);
  });

  it('7521 (dst IP, src client only) keeps dest_ip and names the src client', () => {
    const row = parseMessage(RAW_IPS_DST_ONLY_7521, '2026-11-24T22:36:55.298Z');
    expect(row.source_ip).toBeNull();
    expect(row.dest_ip).toBe('140.82.112.3');
    expect(row.source_client_name).toBe('ian-chesal-ML-MHWDP7TWPR 8e:54');
    expect(row.source_client_mac).toBe('d0:c1:b5:24:8e:54');
    expect(row.dest_client_name).toBeNull();
    expect(row.dest_client_mac).toBeNull();
  });

  it('2026-08-26 sample falls back to the security slug with no source_ip', () => {
    const row = parseMessage(RAW_SECURITY_20260826, '2026-08-27T00:02:04.000Z');
    expect(row.category).toBe('security');
    expect(row.source_ip).toBeNull();
    expect(row.source_client_name).toBe('tranquility');
  });
});
