import { createHmac, timingSafeEqual } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface AuditTrailEntry<T = Record<string, unknown>> {
  algorithm: 'hmac-sha256';
  version: '2.0.0';
  timestamp: number;
  agentId: string;
  organizationId: string | number;
  action: string;
  decision: 'allowed' | 'denied';
  payload: T;
  previousDigest: string | null;
  digest: string;
}

export interface AuditCheckpoint {
  entryCount: number;
  headDigest: string;
}

export class SynterAuditTrail {
  private static readonly VERSION = '2.0.0';
  private static readonly DIGEST_PATTERN = /^[a-f0-9]{64}$/i;
  private readonly secretKey: Buffer;

  constructor(secretKey: string) {
    if (!secretKey || secretKey.trim().length === 0) {
      throw new Error('SynterAuditTrail requires a non-empty secret key.');
    }
    this.secretKey = Buffer.from(secretKey, 'utf-8');
  }

  /**
   * Appends to a single-writer local JSONL ledger. Existing content is fully
   * authenticated before a new entry is written.
   */
  public appendEntry<T = Record<string, unknown>>(
    filePath: string,
    entry: Omit<AuditTrailEntry<T>, 'algorithm' | 'version' | 'previousDigest' | 'digest' | 'timestamp'> & {
      timestamp?: number;
    }
  ): AuditTrailEntry<T> {
    mkdirSync(dirname(filePath), { recursive: true });

    let previousDigest: string | null = null;
    if (existsSync(filePath)) {
      const verification = this.verify(filePath);
      if (!verification.valid) {
        throw new Error(`Cannot append to an invalid audit trail: ${verification.violations.join(' ')}`);
      }
      previousDigest = this.getCheckpoint(filePath).headDigest;
    }

    const timestamp = entry.timestamp ?? Math.floor(Date.now() / 1000);
    this.validateNewEntry(entry, timestamp);
    const baseEntry = {
      algorithm: 'hmac-sha256' as const,
      version: SynterAuditTrail.VERSION as '2.0.0',
      timestamp,
      agentId: entry.agentId,
      organizationId: entry.organizationId,
      action: entry.action,
      decision: entry.decision,
      payload: entry.payload,
      previousDigest
    };
    const digest = this.computeDigest(baseEntry);
    const fullEntry: AuditTrailEntry<T> = { ...baseEntry, digest };

    appendFileSync(filePath, `${JSON.stringify(fullEntry)}\n`, 'utf-8');
    return fullEntry;
  }

  public verify(
    filePath: string,
    expectedCheckpoint?: AuditCheckpoint
  ): { valid: boolean; violations: string[] } {
    if (!existsSync(filePath)) {
      return { valid: false, violations: ['AUDIT_LOG_MISSING: Audit trail file does not exist.'] };
    }

    let lines: string[];
    try {
      lines = this.readLines(filePath);
    } catch (error) {
      return {
        valid: false,
        violations: [`AUDIT_LOG_MALFORMED: ${error instanceof Error ? error.message : 'Unable to read audit trail.'}`]
      };
    }
    if (lines.length === 0) {
      return { valid: false, violations: ['AUDIT_LOG_EMPTY: Audit trail contains no entries.'] };
    }

    const violations: string[] = [];
    if (expectedCheckpoint !== undefined && !this.isValidCheckpoint(expectedCheckpoint)) {
      violations.push('AUDIT_CHECKPOINT_INVALID: Checkpoint contains invalid or unsupported fields.');
    }
    let previousDigest: string | null = null;

    lines.forEach((line, index) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        violations.push(`AUDIT_ENTRY_INVALID_JSON: Entry ${index + 1} is not valid JSON.`);
        return;
      }

      if (line !== JSON.stringify(parsed)) {
        violations.push(`AUDIT_ENTRY_NONCANONICAL: Entry ${index + 1} is not canonical writer output.`);
        return;
      }

      const entryViolations = this.validateStoredEntry(parsed, index + 1);
      if (entryViolations.length > 0) {
        violations.push(...entryViolations);
        return;
      }

      const entry = parsed as AuditTrailEntry;
      const { digest, ...unsignedEntry } = entry;
      if (entry.previousDigest !== previousDigest) {
        violations.push(`AUDIT_CHAIN_BROKEN: Entry ${index + 1} does not link to the previous digest.`);
      }

      const expectedDigest = this.computeDigest(unsignedEntry);
      if (!this.digestsMatch(expectedDigest, digest)) {
        violations.push(`AUDIT_ENTRY_TAMPERED: Entry ${index + 1} digest mismatch.`);
      }
      previousDigest = digest;
    });

    if (expectedCheckpoint !== undefined && this.isValidCheckpoint(expectedCheckpoint) && previousDigest) {
      if (
        expectedCheckpoint.entryCount !== lines.length ||
        !this.digestsMatch(expectedCheckpoint.headDigest, previousDigest)
      ) {
        violations.push('AUDIT_CHECKPOINT_MISMATCH: Audit trail was truncated or replaced with a valid prefix.');
      }
    }

    return { valid: violations.length === 0, violations };
  }

  public getCheckpoint(filePath: string): AuditCheckpoint {
    const verification = this.verify(filePath);
    if (!verification.valid) {
      throw new Error(`Cannot checkpoint an invalid audit trail: ${verification.violations.join(' ')}`);
    }
    const lines = this.readLines(filePath);
    const finalEntry = JSON.parse(lines[lines.length - 1]) as AuditTrailEntry;
    return { entryCount: lines.length, headDigest: finalEntry.digest };
  }

  private readLines(filePath: string): string[] {
    const bytes = readFileSync(filePath);
    const content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (content.length === 0) return [];
    if (!content.endsWith('\n')) throw new Error('Audit trail must end with a newline.');
    const lines = content.slice(0, -1).split('\n');
    if (lines.some((line) => line.length === 0)) throw new Error('Audit trail must not contain blank lines.');
    return lines;
  }

  private validateNewEntry(entry: Record<string, unknown>, timestamp: number): void {
    if (
      typeof entry.agentId !== 'string' ||
      entry.agentId.length === 0 ||
      !this.isValidOrganizationId(entry.organizationId) ||
      typeof entry.action !== 'string' ||
      entry.action.length === 0 ||
      (entry.decision !== 'allowed' && entry.decision !== 'denied') ||
      entry.payload === undefined ||
      !Number.isSafeInteger(timestamp) ||
      timestamp <= 0
    ) {
      throw new Error('Audit entry contains invalid required fields.');
    }
    this.canonicalize(entry.payload);
  }

  private validateStoredEntry(value: unknown, index: number): string[] {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return [`AUDIT_ENTRY_INVALID: Entry ${index} must be an object.`];
    }
    const entry = value as Record<string, unknown>;
    const expectedKeys = [
      'action', 'agentId', 'algorithm', 'decision', 'digest', 'organizationId',
      'payload', 'previousDigest', 'timestamp', 'version'
    ];
    const keys = Object.keys(entry).sort();
    if (keys.length !== expectedKeys.length || keys.some((key, keyIndex) => key !== expectedKeys[keyIndex])) {
      return [`AUDIT_ENTRY_INVALID: Entry ${index} contains missing or unsupported fields.`];
    }
    if (
      entry.algorithm !== 'hmac-sha256' ||
      entry.version !== SynterAuditTrail.VERSION ||
      typeof entry.agentId !== 'string' ||
      entry.agentId.length === 0 ||
      !this.isValidOrganizationId(entry.organizationId) ||
      typeof entry.action !== 'string' ||
      entry.action.length === 0 ||
      (entry.decision !== 'allowed' && entry.decision !== 'denied') ||
      !Number.isSafeInteger(entry.timestamp) ||
      (entry.timestamp as number) <= 0 ||
      (entry.previousDigest !== null && !this.isDigest(entry.previousDigest)) ||
      !this.isDigest(entry.digest)
    ) {
      return [`AUDIT_ENTRY_INVALID: Entry ${index} has invalid field values.`];
    }
    try {
      this.canonicalize(entry.payload);
    } catch {
      return [`AUDIT_ENTRY_INVALID: Entry ${index} payload is not supported JSON.`];
    }
    return [];
  }

  private computeDigest<T>(entry: Omit<AuditTrailEntry<T>, 'digest'>): string {
    return createHmac('sha256', this.secretKey).update(this.canonicalize(entry)).digest('hex');
  }

  private canonicalize(value: unknown): string {
    return JSON.stringify(this.sortValue(value));
  }

  private sortValue(value: unknown): unknown {
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
        throw new Error('Unsupported number.');
      }
      return value;
    }
    if (Array.isArray(value)) return value.map((item) => this.sortValue(item));
    if (value && typeof value === 'object') {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) throw new Error('Unsupported object.');
      return Object.keys(value as Record<string, unknown>).sort().reduce((result, key) => {
        result[key] = this.sortValue((value as Record<string, unknown>)[key]);
        return result;
      }, Object.create(null) as Record<string, unknown>);
    }
    throw new Error('Unsupported value.');
  }

  private isDigest(value: unknown): value is string {
    return typeof value === 'string' && SynterAuditTrail.DIGEST_PATTERN.test(value);
  }

  private isValidOrganizationId(value: unknown): value is string | number {
    return typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value));
  }

  private isValidCheckpoint(value: unknown): value is AuditCheckpoint {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const checkpoint = value as Record<string, unknown>;
    const keys = Object.keys(checkpoint).sort();
    return (
      keys.length === 2 &&
      keys[0] === 'entryCount' &&
      keys[1] === 'headDigest' &&
      Number.isSafeInteger(checkpoint.entryCount) &&
      (checkpoint.entryCount as number) > 0 &&
      this.isDigest(checkpoint.headDigest)
    );
  }

  private digestsMatch(expectedDigest: string, providedDigest: string): boolean {
    if (!this.isDigest(expectedDigest) || !this.isDigest(providedDigest)) return false;
    const expected = Buffer.from(expectedDigest, 'hex');
    const provided = Buffer.from(providedDigest, 'hex');
    return expected.length === provided.length && timingSafeEqual(expected, provided);
  }
}
