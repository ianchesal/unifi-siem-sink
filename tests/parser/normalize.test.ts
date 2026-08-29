import { describe, it, expect } from 'vitest';
import { normalize, unparsedEvent } from '../../src/parser/normalize.js';
import type { CefMessage } from '../../src/parser/cef.js';

function makeCef(overrides: Partial<CefMessage> = {}): CefMessage {
  return {
    version: '0',
    vendor: 'Ubiquiti',
    product: 'UniFi Network',
    deviceVersion: '9.3.33',
    signatureId: '544',
    name: 'Admin Accessed UniFi Network',
    severity: '1',
    extension: {},
    ...overrides,
  };
}

describe('normalize', () => {
  it('maps a known Security/Intrusion Prevention category', () => {
    const cef = makeCef({
      name: 'Threat Detected and Blocked',
      extension: {
        UNIFIcategory: 'Security',
        UNIFIsubCategory: 'Intrusion Prevention',
        src: '10.0.30.5',
        dst: '93.184.216.34',
      },
    });
    const row = normalize(cef, 'raw-message', '2026-08-28T22:00:00.000Z');
    expect(row.category).toBe('ips_alert');
    expect(row.subcategory).toBe('Intrusion Prevention');
    expect(row.source_ip).toBe('10.0.30.5');
    expect(row.dest_ip).toBe('93.184.216.34');
    expect(row.parsed).toBe(1);
    expect(row.raw).toBe('raw-message');
  });

  it('maps Security/Firewall to firewall_block', () => {
    const cef = makeCef({
      extension: { UNIFIcategory: 'Security', UNIFIsubCategory: 'Firewall' },
    });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('firewall_block');
  });

  it('maps Security/Honeypot to honeypot', () => {
    const cef = makeCef({
      extension: { UNIFIcategory: 'Security', UNIFIsubCategory: 'Honeypot' },
    });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('honeypot');
  });

  it('maps System/Admin Activity to admin_action', () => {
    const cef = makeCef({
      extension: { UNIFIcategory: 'System', UNIFIsubCategory: 'Admin' },
    });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('admin_action');
  });

  it('defaults unrecognized category pairs to unknown', () => {
    const cef = makeCef({
      extension: { UNIFIcategory: 'Power', UNIFIsubCategory: 'PoE' },
    });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('unknown');
  });

  it('falls back to UNIFIclientIp when src is absent', () => {
    const cef = makeCef({ extension: { UNIFIclientIp: '192.168.10.178' } });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').source_ip).toBe('192.168.10.178');
  });

  it('rejects an invalid IP and stores null instead', () => {
    const cef = makeCef({ extension: { src: 'not-an-ip' } });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').source_ip).toBeNull();
  });

  it('rejects an out-of-range port and stores null instead', () => {
    const cef = makeCef({ extension: { spt: '99999' } });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').source_port).toBeNull();
  });

  it('accepts a valid port', () => {
    const cef = makeCef({ extension: { spt: '443' } });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').source_port).toBe(443);
  });

  it('parses severity as a number', () => {
    const cef = makeCef({ severity: '7' });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').severity).toBe(7);
  });

  it('stores the CEF msg extension as the message field', () => {
    const cef = makeCef({ extension: { msg: 'hello world' } });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').message).toBe('hello world');
  });

  // Real sample captured from a live UDM Pro (Network app 10.6.101), see
  // tests/fixtures/real-cef-samples.md. Security-category events from this
  // device carry no UNIFIsubCategory key at all; the subtype signal is
  // UNIFIpolicyType instead. The real signature name lives in
  // UNIFIipsSignature (not the standard CEF cs1 key), and the real
  // timestamp is UNIFIutcTime (not the standard CEF rt key).
  it('maps a real IDS/IPS block event (no UNIFIsubCategory, uses UNIFIpolicyType)', () => {
    const cef = makeCef({
      product: 'UniFi Network',
      deviceVersion: '10.6.101',
      signatureId: '201',
      name: 'Threat Detected and Blocked',
      severity: '7',
      extension: {
        UNIFIcategory: 'Security',
        UNIFIhost: 'UDM-Pro',
        proto: 'TCP',
        spt: '53250',
        dpt: '32400',
        act: 'blocked',
        UNIFIpolicyName: 'DShield Block List',
        UNIFIpolicyType: 'IDS/IPS',
        src: '198.235.24.95',
        dst: '192.168.1.26',
        UNIFIipsSignature: 'ET DROP Dshield Block Listed Source group 1',
        UNIFIipsSignatureId: '2402000',
        UNIFIutcTime: '2026-08-29T01:29:30.869Z',
        msg: 'A network intrusion attempt from 198.235.24.95 to 192.168.1.26 has been detected and blocked.',
      },
    });
    const row = normalize(cef, 'raw-ips-block', '2026-08-29T09:29:00.000Z');
    expect(row.category).toBe('ips_alert');
    expect(row.signature).toBe('ET DROP Dshield Block Listed Source group 1');
    expect(row.event_time).toBe('2026-08-29T01:29:30.869Z');
    expect(row.source_ip).toBe('198.235.24.95');
    expect(row.dest_ip).toBe('192.168.1.26');
    expect(row.source_port).toBe(53250);
    expect(row.dest_port).toBe(32400);
    expect(row.protocol).toBe('TCP');
    expect(row.action).toBe('blocked');
    expect(row.severity).toBe(7);
  });

  it('falls back to UNIFIpolicyName for signature when UNIFIipsSignature is absent', () => {
    const cef = makeCef({
      extension: { UNIFIcategory: 'Security', UNIFIpolicyType: 'Firewall', UNIFIpolicyName: 'Block IoT VLAN' },
    });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').signature).toBe('Block IoT VLAN');
  });
});

describe('unparsedEvent', () => {
  it('produces a fully-null row with category unknown and parsed 0', () => {
    const row = unparsedEvent('garbled input', '2026-08-28T22:00:00.000Z');
    expect(row.category).toBe('unknown');
    expect(row.parsed).toBe(0);
    expect(row.raw).toBe('garbled input');
    expect(row.source_ip).toBeNull();
    expect(row.event_time).toBeNull();
  });
});
