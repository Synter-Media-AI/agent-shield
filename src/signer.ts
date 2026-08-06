import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  canonicalJson,
  MAX_SAFE_JSON_INTEGER,
  validateUnicodeString,
  validSecret
} from './canonical.js';

export interface SignedPayloadEnvelope<T = Record<string, unknown>> {
  schema_version: '1.0';
  algorithm: 'hmac-sha256';
  agent_id: string;
  organization_id: string;
  timestamp: number;
  payload: T;
  signature: string;
}

export class SynterAgentSigner {
  public static readonly FUTURE_SKEW_SECONDS = 30;
  private readonly secretKey: Buffer;

  constructor(secretKey: string) {
    this.secretKey = validSecret(secretKey);
  }

  /**
   * Cryptographically signs an agent payload or tool call execution intent.
   */
  public signPayload<T = Record<string, unknown>>(
    agentId: string,
    organizationId: string,
    payload: T,
    timestamp?: number
  ): SignedPayloadEnvelope<T> {
    const ts = timestamp ?? Math.floor(Date.now() / 1000);
    const unsigned = this.validateUnsigned(agentId, organizationId, ts, payload);
    const message = Buffer.concat([Buffer.from('agent-shield/envelope/v1\0'), Buffer.from(canonicalJson(unsigned))]);

    const signature = createHmac('sha256', this.secretKey)
      .update(message)
      .digest('hex');

    return {
      ...unsigned,
      timestamp: ts,
      payload,
      signature
    };
  }

  /**
   * Verifies a signed agent envelope for integrity and timestamp freshness.
   * The host must separately and atomically deduplicate accepted envelopes.
   */
  public verifySignature<T = Record<string, unknown>>(
    envelope: SignedPayloadEnvelope<T>,
    maxAgeSeconds = 300
  ): { valid: boolean; error?: string } {
    try {
      if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new Error();
      if (!hasExactKeys(envelope, [
        'schema_version',
        'algorithm',
        'agent_id',
        'organization_id',
        'timestamp',
        'payload',
        'signature'
      ])) throw new Error();
      const { schema_version, algorithm, agent_id, organization_id, timestamp, payload, signature } = envelope;
      if (schema_version !== '1.0' || algorithm !== 'hmac-sha256' || !/^[a-f0-9]{64}$/.test(signature)) throw new Error();
      if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0) throw new Error();
      const unsigned = this.validateUnsigned(agent_id, organization_id, timestamp, payload);

      const currentTs = Math.floor(Date.now() / 1000);
      if (timestamp < currentTs - maxAgeSeconds || timestamp > currentTs + SynterAgentSigner.FUTURE_SKEW_SECONDS) {
        return { valid: false, error: 'STALE_OR_FUTURE_ENVELOPE: Timestamp outside acceptable window.' };
      }

      const message = Buffer.concat([Buffer.from('agent-shield/envelope/v1\0'), Buffer.from(canonicalJson(unsigned))]);

      const expectedSig = createHmac('sha256', this.secretKey)
        .update(message)
        .digest('hex');

      const expectedBuf = Buffer.from(expectedSig, 'hex');
      const providedBuf = Buffer.from(signature, 'hex');

      if (expectedBuf.length !== providedBuf.length || !timingSafeEqual(expectedBuf, providedBuf)) {
        return { valid: false, error: 'SIGNATURE_MISMATCH: Payload has been tampered with or key is invalid.' };
      }

      return { valid: true };
    } catch {
      return { valid: false, error: 'INVALID_ENVELOPE: Envelope is not valid Agent Shield JSON.' };
    }
  }

  private validateUnsigned<T>(
    agent_id: string,
    organization_id: string,
    timestamp: number,
    payload: T
  ) {
    validateUnicodeString(agent_id, 'agent_id');
    validateUnicodeString(organization_id, 'organization_id');
    if (agent_id.length === 0 || organization_id.length === 0 ||
      !Number.isSafeInteger(timestamp) || timestamp <= 0 || timestamp > MAX_SAFE_JSON_INTEGER ||
      !payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new TypeError('Invalid envelope fields.');
    }
    canonicalJson(payload);
    return { schema_version: '1.0' as const, algorithm: 'hmac-sha256' as const, agent_id, organization_id, timestamp, payload };
  }
}

function hasExactKeys(value: object, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length &&
    actual.every((key, index) => key === [...expected].sort()[index]);
}
