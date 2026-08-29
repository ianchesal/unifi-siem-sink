import { describe, it, expect } from 'vitest';
import { stripEnvelope } from '../../src/parser/envelope.js';

describe('stripEnvelope', () => {
  it('strips an RFC3164-style envelope', () => {
    const raw = '<134>Aug 28 22:00:00 UDM-Pro CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|src=1.2.3.4';
    expect(stripEnvelope(raw)).toBe('CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|src=1.2.3.4');
  });

  it('strips an RFC5424-style envelope', () => {
    const raw = '<134>1 2026-08-28T22:00:00.000Z UDM-Pro unifi - - - CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Name|1|src=1.2.3.4';
    expect(stripEnvelope(raw)).toBe('CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Name|1|src=1.2.3.4');
  });

  it('returns the payload unchanged when there is no envelope', () => {
    const raw = 'CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Name|1|src=1.2.3.4';
    expect(stripEnvelope(raw)).toBe(raw);
  });

  it('returns null when no CEF marker is present', () => {
    expect(stripEnvelope('<134>Aug 28 22:00:00 UDM-Pro some unrelated log line')).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(stripEnvelope('')).toBeNull();
  });
});
