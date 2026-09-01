export interface CefMessage {
  version: string;
  vendor: string;
  product: string;
  deviceVersion: string;
  signatureId: string;
  name: string;
  severity: string;
  extension: Record<string, string>;
}

function parseHeader(body: string): { fields: string[]; extensionStart: number } {
  const fields: string[] = [];
  let current = '';
  let i = 0;
  while (i < body.length && fields.length < 7) {
    const ch = body[i];
    if (ch === '\\' && i + 1 < body.length) {
      current += body[i + 1];
      i += 2;
      continue;
    }
    if (ch === '|') {
      fields.push(current);
      current = '';
      i += 1;
      continue;
    }
    current += ch;
    i += 1;
  }
  return { fields, extensionStart: i };
}

function unescapeCefValue(value: string): string {
  let result = '';
  for (let i = 0; i < value.length; i++) {
    if (value[i] === '\\' && i + 1 < value.length) {
      const next = value[i + 1];
      if (next === '\\') {
        result += '\\';
      } else if (next === '=') {
        result += '=';
      } else if (next === 'n') {
        result += '\n';
      } else {
        result += next;
      }
      i += 1;
      continue;
    }
    result += value[i];
  }
  return result;
}

function parseExtension(extensionRaw: string): Record<string, string> {
  const extension: Record<string, string> = {};
  const keyPattern = /([A-Za-z][A-Za-z0-9._]*)=/g;
  const matches = [...extensionRaw.matchAll(keyPattern)];
  for (let m = 0; m < matches.length; m++) {
    const key = matches[m][1];
    const idx = matches[m].index ?? 0;
    const valueStart = idx + matches[m][0].length;
    const nextIdx = matches[m + 1]?.index ?? extensionRaw.length;
    const valueEnd = m + 1 < matches.length ? nextIdx : extensionRaw.length;
    extension[key] = unescapeCefValue(extensionRaw.slice(valueStart, valueEnd).trim());
  }
  return extension;
}

export function parseCef(payload: string): CefMessage | null {
  if (!payload.startsWith('CEF:')) return null;
  const { fields, extensionStart } = parseHeader(payload.slice(4));
  if (fields.length < 7) return null;

  const [version, vendor, product, deviceVersion, signatureId, name, severity] = fields;
  const extension = parseExtension(payload.slice(4 + extensionStart));

  return { version, vendor, product, deviceVersion, signatureId, name, severity, extension };
}
