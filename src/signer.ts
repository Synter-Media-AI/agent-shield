import { createHmac, timingSafeEqual } from 'node:crypto';

export interface SignedPayloadEnvelope<T = Record<string, unknown>> {
  agentId: string;
  organizationId: string | number;
  timestamp: number;
  payload: T;
  signature: string;
}

export class SynterAgentSigner {
  private static readonly SIGNATURE_PROTOCOL = 'synter.intent.v2';
  private static readonly SIGNATURE_HEX_LENGTH = 64;
  private static readonly MAX_CLOCK_SKEW_SECONDS = 30;
  private readonly secretKey: Buffer;

  constructor(secretKey: string) {
    if (typeof secretKey !== 'string' || Buffer.byteLength(secretKey, 'utf-8') < 32) {
      throw new Error('SynterAgentSigner requires a secret key containing at least 32 UTF-8 bytes.');
    }
    this.validateUnicode(secretKey);
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
    this.validateSigningInputs(agentId, organizationId, payload, ts);
    const message = this.buildSignatureMessage(agentId, organizationId, ts, payload);

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
    envelope: SignedPayloadEnvelope<T> | unknown,
    maxAgeSeconds = 300
  ): { valid: boolean; error?: string } {
    if (!Number.isFinite(maxAgeSeconds) || !Number.isInteger(maxAgeSeconds) || maxAgeSeconds < 0) {
      return { valid: false, error: 'INVALID_MAX_AGE: maxAgeSeconds must be a finite nonnegative integer.' };
    }

    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      return { valid: false, error: 'INVALID_ENVELOPE: Envelope must be an object.' };
    }

    const envelopeRecord = envelope as Record<string, unknown>;
    const expectedKeys = ['agentId', 'organizationId', 'payload', 'signature', 'timestamp'];
    const actualKeys = Object.keys(envelopeRecord).sort();
    if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
      return { valid: false, error: 'INVALID_ENVELOPE: Envelope contains missing or unsupported fields.' };
    }

    const { agentId, organizationId, timestamp, payload, signature } = envelopeRecord;

    if (
      typeof agentId !== 'string' ||
      agentId.length === 0 ||
      !this.isValidOrganizationId(organizationId) ||
      typeof timestamp !== 'number' ||
      !Number.isInteger(timestamp) ||
      timestamp <= 0 ||
      payload === undefined ||
      payload === null ||
      typeof signature !== 'string' ||
      signature.length !== SynterAgentSigner.SIGNATURE_HEX_LENGTH ||
      !/^[a-f0-9]+$/i.test(signature)
    ) {
      return { valid: false, error: 'INVALID_ENVELOPE: Missing required fields.' };
    }

    try {
      this.encodeValue({ agentId, organizationId, payload });
    } catch {
      return { valid: false, error: 'INVALID_ENVELOPE: Payload must contain only supported JSON values.' };
    }

    const currentTs = Math.floor(Date.now() / 1000);
    if (timestamp > currentTs + SynterAgentSigner.MAX_CLOCK_SKEW_SECONDS) {
      return { valid: false, error: 'FUTURE_TIMESTAMP_REJECTED: Timestamp is too far in the future.' };
    }

    if (currentTs - timestamp > maxAgeSeconds) {
      return { valid: false, error: 'REPLAY_ATTACK_PREVENTED: Timestamp outside acceptable window.' };
    }

    let message: string;
    try {
      message = this.buildSignatureMessage(agentId, organizationId, timestamp, payload);
    } catch {
      return { valid: false, error: 'INVALID_ENVELOPE: Payload contains unsupported values.' };
    }

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

  private buildSignatureMessage(
    agentId: string,
    organizationId: string | number,
    timestamp: number,
    payload: unknown
  ): string {
    return JSON.stringify(this.encodeValue({
      protocol: SynterAgentSigner.SIGNATURE_PROTOCOL,
      agentId,
      organizationId,
      timestamp,
      payload
    }));
  }

  private encodeValue(value: unknown): unknown {
    if (value === null) {
      return ['null'];
    }

    if (typeof value === 'boolean') {
      return ['boolean', value];
    }

    if (typeof value === 'string') {
      this.validateUnicode(value);
      return ['string', value];
    }

    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        throw new Error('Unsupported number.');
      }
      const buffer = Buffer.allocUnsafe(8);
      buffer.writeDoubleBE(value);
      return ['number', buffer.toString('hex')];
    }

    if (Array.isArray(value)) {
      return ['array', value.map((entry) => this.encodeValue(entry))];
    }

    if (value && typeof value === 'object') {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new Error('Only plain objects are supported.');
      }

      const keys = Object.keys(value as Record<string, unknown>);
      keys.forEach((key) => this.validateUnicode(key));
      const entries = keys
        .sort((first, second) => Buffer.compare(Buffer.from(first), Buffer.from(second)))
        .map((key) => [key, this.encodeValue((value as Record<string, unknown>)[key])]);
      return ['object', entries];
    }

    throw new Error('Unsupported value.');
  }

  private validateSigningInputs(
    agentId: string,
    organizationId: string | number,
    payload: unknown,
    timestamp: number
  ): void {
    if (typeof agentId !== 'string' || agentId.length === 0) {
      throw new Error('agentId must be a non-empty string.');
    }
    if (!this.isValidOrganizationId(organizationId)) {
      throw new Error('organizationId must be a string or safe integer.');
    }
    if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
      throw new Error('timestamp must be a positive safe integer.');
    }
    if (payload === null) {
      throw new Error('payload must not be null.');
    }
    this.encodeValue({ agentId, organizationId, payload });
  }

  private isValidOrganizationId(value: unknown): value is string | number {
    return typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value));
  }

  private validateUnicode(value: string): void {
    for (const character of value) {
      const codePoint = character.codePointAt(0)!;
      if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
        throw new Error('Strings must contain valid Unicode scalar values.');
      }
    }
  }
}
