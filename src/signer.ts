import { createHmac, timingSafeEqual } from 'node:crypto';

export interface SignedPayloadEnvelope<T = Record<string, unknown>> {
  agentId: string;
  organizationId: string | number;
  timestamp: number;
  payload: T;
  signature: string;
}

export class SynterAgentSigner {
  private readonly secretKey: Buffer;

  constructor(secretKey: string) {
    if (!secretKey || secretKey.trim().length === 0) {
      throw new Error('SynterAgentSigner requires a non-empty secret key.');
    }
    this.secretKey = Buffer.from(secretKey, 'utf-8');
  }

  /**
   * Cryptographically signs an agent payload or tool call execution intent.
   */
  public signPayload<T = Record<string, unknown>>(
    agentId: string,
    organizationId: string | number,
    payload: T,
    timestamp?: number
  ): SignedPayloadEnvelope<T> {
    const ts = timestamp ?? Math.floor(Date.now() / 1000);
    const canonicalPayload = JSON.stringify(payload, Object.keys(payload as object).sort());
    const message = `${agentId}:${organizationId}:${ts}:${canonicalPayload}`;

    const signature = createHmac('sha256', this.secretKey)
      .update(message, 'utf-8')
      .digest('hex');

    return {
      agentId,
      organizationId,
      timestamp: ts,
      payload,
      signature
    };
  }

  /**
   * Verifies a signed agent envelope for payload integrity and replay prevention.
   */
  public verifySignature<T = Record<string, unknown>>(
    envelope: SignedPayloadEnvelope<T>,
    maxAgeSeconds = 300
  ): { valid: boolean; error?: string } {
    const { agentId, organizationId, timestamp, payload, signature } = envelope;

    if (!agentId || !organizationId || !timestamp || !payload || !signature) {
      return { valid: false, error: 'INVALID_ENVELOPE: Missing required fields.' };
    }

    const currentTs = Math.floor(Date.now() / 1000);
    if (Math.abs(currentTs - timestamp) > maxAgeSeconds) {
      return { valid: false, error: 'REPLAY_ATTACK_PREVENTED: Timestamp outside acceptable window.' };
    }

    const canonicalPayload = JSON.stringify(payload, Object.keys(payload as object).sort());
    const message = `${agentId}:${organizationId}:${timestamp}:${canonicalPayload}`;

    const expectedSig = createHmac('sha256', this.secretKey)
      .update(message, 'utf-8')
      .digest('hex');

    const expectedBuf = Buffer.from(expectedSig, 'utf-8');
    const providedBuf = Buffer.from(signature, 'utf-8');

    if (expectedBuf.length !== providedBuf.length || !timingSafeEqual(expectedBuf, providedBuf)) {
      return { valid: false, error: 'SIGNATURE_MISMATCH: Payload has been tampered with or key is invalid.' };
    }

    return { valid: true };
  }
}
