import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface AuditTrailEntry<T = Record<string, unknown>> {
  timestamp: number;
  agentId: string;
  organizationId: string | number;
  action: string;
  decision: 'allowed' | 'denied';
  payload: T;
  previousDigest: string | null;
  digest: string;
}

export class SynterAuditTrail {
  /**
   * Appends a decision record to a local JSONL ledger with hash chaining so a
   * runtime can detect tampering in the exported audit file.
   */
  public appendEntry<T = Record<string, unknown>>(
    filePath: string,
    entry: Omit<AuditTrailEntry<T>, 'previousDigest' | 'digest' | 'timestamp'> & { timestamp?: number }
  ): AuditTrailEntry<T> {
    mkdirSync(dirname(filePath), { recursive: true });

    const previousDigest = this.readLastDigest(filePath);
    const timestamp = entry.timestamp ?? Math.floor(Date.now() / 1000);
    const baseEntry = {
      timestamp,
      agentId: entry.agentId,
      organizationId: entry.organizationId,
      action: entry.action,
      decision: entry.decision,
      payload: entry.payload,
      previousDigest
    };
    const digest = createHash('sha256').update(JSON.stringify(baseEntry)).digest('hex');
    const fullEntry: AuditTrailEntry<T> = { ...baseEntry, digest };

    appendFileSync(filePath, `${JSON.stringify(fullEntry)}\n`, 'utf-8');
    return fullEntry;
  }

  public verify(filePath: string): { valid: boolean; violations: string[] } {
    if (!existsSync(filePath)) {
      return { valid: false, violations: ['AUDIT_LOG_MISSING: Audit trail file does not exist.'] };
    }

    const lines = readFileSync(filePath, 'utf-8')
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
    const violations: string[] = [];
    let previousDigest: string | null = null;

    lines.forEach((line, index) => {
      const entry = JSON.parse(line) as AuditTrailEntry;
      const { digest, ...unsignedEntry } = entry;

      if (entry.previousDigest !== previousDigest) {
        violations.push(`AUDIT_CHAIN_BROKEN: Entry ${index + 1} does not link to the previous digest.`);
      }

      const expectedDigest = createHash('sha256').update(JSON.stringify(unsignedEntry)).digest('hex');
      if (expectedDigest !== digest) {
        violations.push(`AUDIT_ENTRY_TAMPERED: Entry ${index + 1} digest mismatch.`);
      }

      previousDigest = digest;
    });

    return { valid: violations.length === 0, violations };
  }

  private readLastDigest(filePath: string): string | null {
    if (!existsSync(filePath)) {
      return null;
    }

    const lines = readFileSync(filePath, 'utf-8')
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);

    if (lines.length === 0) {
      return null;
    }

    const lastEntry = JSON.parse(lines[lines.length - 1]) as AuditTrailEntry;
    return lastEntry.digest;
  }
}
