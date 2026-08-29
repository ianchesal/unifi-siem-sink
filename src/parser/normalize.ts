import type { CefMessage } from './cef.js';

export interface EventRow {
  received_at: string;
  event_time: string | null;
  category: string;
  subcategory: string | null;
  severity: number | null;
  name: string | null;
  source_ip: string | null;
  dest_ip: string | null;
  source_port: number | null;
  dest_port: number | null;
  protocol: string | null;
  action: string | null;
  signature: string | null;
  message: string | null;
  device_host: string | null;
  raw: string;
  parsed: 0 | 1;
}

const CATEGORY_MAP: Record<string, string> = {
  'Security|Intrusion Prevention': 'ips_alert',
  'Security|Firewall': 'firewall_block',
  'Security|Honeypot': 'honeypot',
  'System|Admin': 'admin_action',
};

const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;

function isValidIpv4(ip: string): boolean {
  if (!IPV4_PATTERN.test(ip)) return false;
  return ip.split('.').every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
}

function isValidIpv6(ip: string): boolean {
  return ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip);
}

function validIpOrNull(value: string | undefined): string | null {
  if (!value) return null;
  return isValidIpv4(value) || isValidIpv6(value) ? value : null;
}

function validPortOrNull(value: string | undefined): number | null {
  if (!value) return null;
  const port = Number(value);
  return Number.isInteger(port) && port >= 0 && port <= 65535 ? port : null;
}

function validEventTime(rt: string | undefined): string | null {
  if (!rt) return null;
  const asNumber = Number(rt);
  const date = Number.isFinite(asNumber) && rt.trim() !== '' ? new Date(asNumber) : new Date(rt);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function normalize(cef: CefMessage, raw: string, receivedAt: string): EventRow {
  const ext = cef.extension;
  const categoryKey = `${ext.UNIFIcategory ?? ''}|${ext.UNIFIsubCategory ?? ''}`;
  const severityNum = Number(cef.severity);

  return {
    received_at: receivedAt,
    event_time: validEventTime(ext.rt),
    category: CATEGORY_MAP[categoryKey] ?? 'unknown',
    subcategory: ext.UNIFIsubCategory ?? null,
    severity: Number.isFinite(severityNum) ? severityNum : null,
    name: cef.name || null,
    source_ip: validIpOrNull(ext.src ?? ext.UNIFIclientIp ?? ext.UNIFIdeviceIp),
    dest_ip: validIpOrNull(ext.dst),
    source_port: validPortOrNull(ext.spt),
    dest_port: validPortOrNull(ext.dpt),
    protocol: ext.proto ?? null,
    action: ext.act ?? null,
    signature: ext.cs1 ?? (cef.signatureId || null),
    message: ext.msg ?? null,
    device_host: ext.UNIFIhost ?? null,
    raw,
    parsed: 1,
  };
}

export function unparsedEvent(raw: string, receivedAt: string): EventRow {
  return {
    received_at: receivedAt,
    event_time: null,
    category: 'unknown',
    subcategory: null,
    severity: null,
    name: null,
    source_ip: null,
    dest_ip: null,
    source_port: null,
    dest_port: null,
    protocol: null,
    action: null,
    signature: null,
    message: null,
    device_host: null,
    raw,
    parsed: 0,
  };
}
