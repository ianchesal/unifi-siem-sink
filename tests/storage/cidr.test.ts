import { describe, it, expect } from 'vitest';
import { ipInCidr } from '../../src/storage/cidr.js';

describe('ipInCidr', () => {
  it('matches an IP within a /24', () => {
    expect(ipInCidr('10.0.30.5', '10.0.30.0/24')).toBe(true);
  });

  it('rejects an IP outside a /24', () => {
    expect(ipInCidr('10.0.31.5', '10.0.30.0/24')).toBe(false);
  });

  it('matches an exact /32', () => {
    expect(ipInCidr('10.0.30.5', '10.0.30.5/32')).toBe(true);
    expect(ipInCidr('10.0.30.6', '10.0.30.5/32')).toBe(false);
  });

  it('matches everything for /0', () => {
    expect(ipInCidr('1.2.3.4', '0.0.0.0/0')).toBe(true);
  });

  it('returns false for a malformed IP', () => {
    expect(ipInCidr('not-an-ip', '10.0.30.0/24')).toBe(false);
  });

  it('returns false for a malformed CIDR', () => {
    expect(ipInCidr('10.0.30.5', 'not-a-cidr')).toBe(false);
  });

  it('returns false for an out-of-range prefix length', () => {
    expect(ipInCidr('10.0.30.5', '10.0.30.0/33')).toBe(false);
  });
});
