import * as canonicalizePackage from 'canonicalize';

const canonicalize = ((canonicalizePackage as unknown as { default?: (value: unknown) => string | undefined }).default
  ?? canonicalizePackage) as unknown as (value: unknown) => string | undefined;

export const MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991;

export function validateUnicodeString(value: unknown, label = 'JSON string'): asserts value is string {
  if (typeof value !== 'string' || hasLoneSurrogate(value)) {
    throw new TypeError(`${label} must be valid Unicode without lone UTF-16 surrogates.`);
  }
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xD800 && codeUnit <= 0xDBFF) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xDC00 && next <= 0xDFFF)) return true;
      index += 1;
    } else if (codeUnit >= 0xDC00 && codeUnit <= 0xDFFF) {
      return true;
    }
  }
  return false;
}

export function canonicalJson(value: unknown): string {
  validateJson(value);
  const result = canonicalize(value);
  if (result === undefined) throw new TypeError('Unsupported JSON value.');
  return result;
}

export function validateJson(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    validateUnicodeString(value);
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new TypeError('JSON numbers must be finite and integers must be safe IEEE-754 integers.');
    }
    return;
  }
  if (typeof value !== 'object') throw new TypeError('Unsupported JSON value.');
  if (seen.has(value)) throw new TypeError('Cyclic JSON value.');
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) validateJson(item, seen);
  } else {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new TypeError('JSON objects must be plain objects.');
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      validateUnicodeString(key, 'JSON object key');
      validateJson(item, seen);
    }
  }
  seen.delete(value);
}

export function validSecret(secretKey: string): Buffer {
  validateUnicodeString(secretKey, 'Secret key');
  if (Buffer.byteLength(secretKey, 'utf8') < 32) {
    throw new Error('Secret key must contain at least 32 UTF-8 bytes.');
  }
  return Buffer.from(secretKey, 'utf8');
}
