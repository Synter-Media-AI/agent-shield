import { createHmac, timingSafeEqual } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalJson, MAX_SAFE_JSON_INTEGER, validSecret } from './canonical.js';

export interface AuditTrailEntry<T = Record<string, unknown>> {
  schema_version: '1.0';
  algorithm: 'hmac-sha256';
  timestamp: number;
  agent_id: string;
  organization_id: string;
  action: string;
  decision: 'allowed' | 'denied';
  payload: T;
  previous_digest: string | null;
  digest: string;
}
type AuditInput<T> = Omit<
  AuditTrailEntry<T>,
  'schema_version' | 'algorithm' | 'previous_digest' | 'digest' | 'timestamp'
> & { timestamp?: number };

export class SynterAuditTrail {
  private readonly key: Buffer;
  constructor(secretKey: string) {
    this.key = validSecret(secretKey);
  }

  public appendEntry<T = Record<string, unknown>>(filePath: string, entry: AuditInput<T>): AuditTrailEntry<T> {
    mkdirSync(dirname(filePath), { recursive: true });
    if (existsSync(filePath)) {
      const check = this.verify(filePath);
      if (!check.valid) throw new Error(`Refusing to append to invalid audit log: ${check.violations.join(' ')}`);
    }
    const previous_digest = this.lastDigest(filePath);
    const unsigned = {
      schema_version: '1.0' as const,
      algorithm: 'hmac-sha256' as const,
      timestamp: entry.timestamp ?? Math.floor(Date.now() / 1000),
      agent_id: entry.agent_id,
      organization_id: entry.organization_id,
      action: entry.action,
      decision: entry.decision,
      payload: entry.payload,
      previous_digest
    };
    this.validateUnsigned(unsigned);
    const full = { ...unsigned, digest: this.digest(unsigned) };
    appendFileSync(filePath, `${JSON.stringify(full)}\n`, 'utf8');
    return full;
  }

  public verify(filePath: string): { valid: boolean; violations: string[] } {
    if (!existsSync(filePath)) return { valid: false, violations: ['AUDIT_LOG_MISSING'] };
    const lines = readFileSync(filePath, 'utf8').split('\n').filter((x) => x.length > 0);
    if (lines.length === 0) return { valid: false, violations: ['AUDIT_LOG_EMPTY'] };
    const violations: string[] = [];
    let previous: string | null = null;
    lines.forEach((line, i) => {
      try {
        const value: unknown = JSON.parse(line);
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
        const entry = value as AuditTrailEntry;
        const expectedKeys = [
          'action', 'agent_id', 'algorithm', 'decision', 'digest', 'organization_id',
          'payload', 'previous_digest', 'schema_version', 'timestamp'
        ];
        if (Object.keys(entry).sort().join('\0') !== expectedKeys.join('\0')) throw new Error();
        const { digest, ...unsigned } = entry;
        this.validateUnsigned(unsigned);
        if (entry.previous_digest !== previous) violations.push(`AUDIT_CHAIN_BROKEN: Entry ${i + 1}.`);
        const expected = this.digest(unsigned);
        if (!/^[a-f0-9]{64}$/.test(digest ?? '') || !timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(digest, 'hex'))) {
          violations.push(`AUDIT_ENTRY_TAMPERED: Entry ${i + 1}.`);
        }
        previous = digest;
      } catch {
        violations.push(`AUDIT_ENTRY_MALFORMED: Entry ${i + 1}.`);
      }
    });
    return { valid: violations.length === 0, violations };
  }
  private digest(value: unknown): string {
    return createHmac('sha256', this.key)
      .update(Buffer.concat([
        Buffer.from('agent-shield/audit/v1\0'),
        Buffer.from(canonicalJson(value))
      ]))
      .digest('hex');
  }
  private lastDigest(path: string): string | null {
    if (!existsSync(path)) return null;
    const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
    return lines.length ? (JSON.parse(lines[lines.length - 1]) as AuditTrailEntry).digest : null;
  }
  private validateUnsigned<T>(value: Omit<AuditTrailEntry<T>, 'digest'>): void {
    if (value.schema_version !== '1.0' || value.algorithm !== 'hmac-sha256' ||
      !Number.isSafeInteger(value.timestamp) || value.timestamp <= 0 ||
      value.timestamp > MAX_SAFE_JSON_INTEGER || typeof value.agent_id !== 'string' ||
      !value.agent_id || typeof value.organization_id !== 'string' || !value.organization_id ||
      typeof value.action !== 'string' || !value.action ||
      !['allowed', 'denied'].includes(value.decision) ||
      (value.previous_digest !== null && !/^[a-f0-9]{64}$/.test(value.previous_digest))) throw new Error('Malformed audit entry');
    canonicalJson(value.payload);
  }
}
