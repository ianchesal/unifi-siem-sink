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

  it('falls back to a slugified category for unrecognized category pairs', () => {
    const cef = makeCef({
      extension: { UNIFIcategory: 'Power', UNIFIsubCategory: 'PoE' },
    });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('power');
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

  // Real samples (tests/fixtures/real-cef-samples.md) show UNIFIcategory
  // values far more varied than the hand-mapped security taxonomy this
  // project cares about most: "Internet and WAN", "UniFi Devices",
  // "Software Updates", and a Security event with neither UNIFIsubCategory
  // nor UNIFIpolicyType. An unmapped-but-known category should fall back
  // to a normalized slug of the real value, not the generic 'unknown'
  // string reserved for genuine parse failures.
  it('falls back to a slugified UNIFIcategory when no specific mapping exists', () => {
    const cef = makeCef({ extension: { UNIFIcategory: 'Internet and WAN' } });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('internet_and_wan');
  });

  it('slugifies a multi-word UNIFIcategory with mixed case', () => {
    const cef = makeCef({ extension: { UNIFIcategory: 'UniFi Devices' } });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('unifi_devices');
  });

  it('slugifies a single-word UNIFIcategory', () => {
    const cef = makeCef({ extension: { UNIFIcategory: 'Security' } });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('security');
  });

  it('still defaults to unknown when UNIFIcategory is entirely absent', () => {
    const cef = makeCef({ extension: {} });
    expect(normalize(cef, 'raw', '2026-08-28T22:00:00.000Z').category).toBe('unknown');
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

describe('normalize: source attribution and client identity', () => {
  const T = '2026-11-25T15:16:13.735Z';
  const securityExt = {
    UNIFIcategory: 'Security',
    UNIFIpolicyType: 'IDS/IPS',
    UNIFIdeviceIp: '192.168.1.1',
  };

  it('does not fall back to UNIFIdeviceIp for Security events', () => {
    const row = normalize(
      makeCef({
        extension: {
          ...securityExt,
          UNIFIsrcClientAlias: 'tranquility',
          UNIFIsrcClientHostname: 'tranquility',
          UNIFIsrcClientMac: '1c:1b:0d:18:07:53',
        },
      }),
      'raw',
      T
    );
    expect(row.source_ip).toBeNull();
    expect(row.source_client_name).toBe('tranquility');
    expect(row.source_client_mac).toBe('1c:1b:0d:18:07:53');
  });

  it('keeps UNIFIdeviceIp fallback for Internet and WAN events', () => {
    const row = normalize(
      makeCef({ extension: { UNIFIcategory: 'Internet and WAN', UNIFIdeviceIp: '192.168.1.1' } }),
      'raw',
      T
    );
    expect(row.category).toBe('internet_and_wan');
    expect(row.source_ip).toBe('192.168.1.1');
  });

  it('uses src for Security events when present', () => {
    const row = normalize(makeCef({ extension: { ...securityExt, src: '10.0.30.5' } }), 'raw', T);
    expect(row.source_ip).toBe('10.0.30.5');
  });

  it('uses UNIFIclientIp for Security events without src', () => {
    const row = normalize(
      makeCef({ extension: { ...securityExt, UNIFIclientIp: '10.0.30.7' } }),
      'raw',
      T
    );
    expect(row.source_ip).toBe('10.0.30.7');
  });

  it('drops dst client fields when they repeat the src client (MAC compared case-insensitively)', () => {
    const row = normalize(
      makeCef({
        extension: {
          ...securityExt,
          UNIFIsrcClientAlias: 'tranquility',
          UNIFIsrcClientMac: '1C:1B:0D:18:07:53',
          UNIFIdstClientAlias: 'tranquility',
          UNIFIdstClientMac: '1c:1b:0d:18:07:53',
        },
      }),
      'raw',
      T
    );
    expect(row.source_client_mac).toBe('1c:1b:0d:18:07:53');
    expect(row.dest_client_name).toBeNull();
    expect(row.dest_client_mac).toBeNull();
  });

  it('drops dst client fields by name when both MACs are absent', () => {
    const row = normalize(
      makeCef({
        extension: { ...securityExt, UNIFIsrcClientAlias: 'nas', UNIFIdstClientAlias: 'nas' },
      }),
      'raw',
      T
    );
    expect(row.source_client_name).toBe('nas');
    expect(row.dest_client_name).toBeNull();
    expect(row.dest_client_mac).toBeNull();
  });

  it('keeps dst client fields for a different client', () => {
    const row = normalize(
      makeCef({
        extension: {
          ...securityExt,
          UNIFIsrcClientAlias: 'laptop',
          UNIFIsrcClientMac: 'aa:aa:aa:aa:aa:aa',
          UNIFIdstClientAlias: 'nas',
          UNIFIdstClientMac: 'bb:bb:bb:bb:bb:bb',
        },
      }),
      'raw',
      T
    );
    expect(row.dest_client_name).toBe('nas');
    expect(row.dest_client_mac).toBe('bb:bb:bb:bb:bb:bb');
  });

  it('falls back to hostname when alias is missing', () => {
    const row = normalize(
      makeCef({ extension: { ...securityExt, UNIFIsrcClientHostname: 'tranquility' } }),
      'raw',
      T
    );
    expect(row.source_client_name).toBe('tranquility');
  });

  it('stores MAC with null name when only MAC is given', () => {
    const row = normalize(
      makeCef({ extension: { ...securityExt, UNIFIsrcClientMac: 'AA:BB:CC:DD:EE:FF' } }),
      'raw',
      T
    );
    expect(row.source_client_name).toBeNull();
    expect(row.source_client_mac).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('leaves client fields null when the event names no client', () => {
    const row = normalize(makeCef({ extension: { ...securityExt, src: '10.0.30.5' } }), 'raw', T);
    expect(row.source_client_name).toBeNull();
    expect(row.source_client_mac).toBeNull();
    expect(row.dest_client_name).toBeNull();
    expect(row.dest_client_mac).toBeNull();
  });

  it('unparsedEvent sets client fields to null', () => {
    const row = unparsedEvent('garbled', T);
    expect(row.source_client_name).toBeNull();
    expect(row.source_client_mac).toBeNull();
    expect(row.dest_client_name).toBeNull();
    expect(row.dest_client_mac).toBeNull();
  });
});
