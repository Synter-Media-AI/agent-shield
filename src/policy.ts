import { MAX_SAFE_JSON_INTEGER } from './canonical.js';
import { SynterAgentSigner, type SignedPayloadEnvelope } from './signer.js';

export interface BudgetMutationPayload {
  action: string;
  campaign_id: string;
  current_budget: number;
  proposed_budget: number;
}

export interface BudgetChangeEvent {
  campaign_id: string;
  timestamp: number;
  percent_increase: number;
}

export interface ExecutionPolicy {
  allowedActions?: string[];
  budgetMutationActions?: string[];
  maxSignatureAgeSeconds?: number;
  maxSingleBudgetIncreasePercent?: number;
  maxCumulativeBudgetIncreasePercent24h?: number;
}

export interface ExecutionPolicyContext {
  recentBudgetChanges?: BudgetChangeEvent[];
}

export interface ExecutionDecision {
  allowed: boolean;
  violations: string[];
  budgetIncreasePercent?: number;
}

interface PolicySnapshot {
  readonly allowedActions: readonly string[];
  readonly budgetMutationActions: readonly string[];
  readonly maxSignatureAgeSeconds: number;
  readonly maxSingleBudgetIncreasePercent: number;
  readonly maxCumulativeBudgetIncreasePercent24h: number;
}

const DEFAULT_BUDGET_ACTIONS = ['SET_BUDGET', 'UNCAP_BUDGET', 'UPDATE_BUDGET'];

export class SynterExecutionGuard {
  private readonly signer: SynterAgentSigner;
  private readonly policy?: Readonly<PolicySnapshot>;

  constructor(secretKey: string, policy: unknown = {}) {
    this.signer = new SynterAgentSigner(secretKey);
    this.policy = this.snapshotPolicy(policy);
  }

  public authorize(envelope: SignedPayloadEnvelope, context: unknown = {}): ExecutionDecision {
    if (!this.policy) {
      return { allowed: false, violations: ['INVALID_POLICY: Policy configuration is malformed.'] };
    }
    if (!isPlainObject(context)) {
      return { allowed: false, violations: ['INVALID_CONTEXT: Execution context must be an object.'] };
    }
    const contextKeys = Object.keys(context);
    if (contextKeys.some((key) => key !== 'recentBudgetChanges')) {
      return { allowed: false, violations: ['INVALID_CONTEXT: Execution context is malformed.'] };
    }

    const verification = this.signer.verifySignature(envelope, this.policy.maxSignatureAgeSeconds);
    if (!verification.valid) {
      return { allowed: false, violations: [verification.error ?? 'SIGNATURE_INVALID'] };
    }

    const payload = envelope.payload;
    if (!isPlainObject(payload)) {
      return { allowed: false, violations: ['INVALID_ACTION: Payload must be an object.'] };
    }
    const action = payload.action;
    if (typeof action !== 'string' || !action) {
      return { allowed: false, violations: ['INVALID_ACTION: action must be a non-empty string.'] };
    }

    const violations: string[] = [];
    if (this.policy.allowedActions.length && !this.policy.allowedActions.includes(action)) {
      violations.push(`ACTION_NOT_ALLOWED: Action '${action}' is not permitted by policy.`);
    }
    if (!this.policy.budgetMutationActions.includes(action)) {
      return { allowed: violations.length === 0, violations };
    }

    const campaign = payload.campaign_id;
    const current = payload.current_budget;
    const proposed = payload.proposed_budget;
    if (typeof campaign !== 'string' || !campaign || !isFiniteNumber(current) || current <= 0 ||
      !isFiniteNumber(proposed) || proposed < 0) {
      violations.push(
        'INVALID_BUDGET_MUTATION: campaign_id, current_budget > 0, and proposed_budget >= 0 are required.'
      );
      return { allowed: false, violations };
    }

    const increase = proposed > current ? ((proposed - current) / current) * 100 : 0;
    if (increase > this.policy.maxSingleBudgetIncreasePercent) {
      violations.push('BUDGET_STEP_CAP_EXCEEDED: Proposed increase exceeds the single-action cap.');
    }

    const history = Object.prototype.hasOwnProperty.call(context, 'recentBudgetChanges')
      ? context.recentBudgetChanges
      : [];
    if (!isValidHistory(history)) {
      violations.push('INVALID_BUDGET_HISTORY: Recent budget history is malformed.');
      return { allowed: false, violations, budgetIncreasePercent: increase };
    }

    const since = Math.floor(Date.now() / 1000) - 86_400;
    const cumulative = increase + history
      .filter((event) => event.campaign_id === campaign && event.timestamp >= since)
      .reduce((total, event) => total + event.percent_increase, 0);
    if (cumulative > this.policy.maxCumulativeBudgetIncreasePercent24h) {
      violations.push(
        'BUDGET_24H_CAP_EXCEEDED: Proposed cumulative increase exceeds the 24-hour cap.'
      );
    }

    return { allowed: violations.length === 0, violations, budgetIncreasePercent: increase };
  }

  private snapshotPolicy(value: unknown): Readonly<PolicySnapshot> | undefined {
    if (!isPlainObject(value)) return undefined;
    const allowedKeys = new Set([
      'allowedActions',
      'budgetMutationActions',
      'maxSignatureAgeSeconds',
      'maxSingleBudgetIncreasePercent',
      'maxCumulativeBudgetIncreasePercent24h'
    ]);
    if (Object.keys(value).some((key) => !allowedKeys.has(key))) return undefined;

    const allowedActions = Object.prototype.hasOwnProperty.call(value, 'allowedActions')
      ? value.allowedActions
      : [];
    const budgetMutationActions = Object.prototype.hasOwnProperty.call(value, 'budgetMutationActions')
      ? value.budgetMutationActions
      : DEFAULT_BUDGET_ACTIONS;
    const maxSignatureAgeSeconds = Object.prototype.hasOwnProperty.call(value, 'maxSignatureAgeSeconds')
      ? value.maxSignatureAgeSeconds
      : 300;
    const maxSingleBudgetIncreasePercent = Object.prototype.hasOwnProperty.call(
      value,
      'maxSingleBudgetIncreasePercent'
    ) ? value.maxSingleBudgetIncreasePercent : 30;
    const maxCumulativeBudgetIncreasePercent24h = Object.prototype.hasOwnProperty.call(
      value,
      'maxCumulativeBudgetIncreasePercent24h'
    ) ? value.maxCumulativeBudgetIncreasePercent24h : 30;

    if (!isStringArray(allowedActions) || !isStringArray(budgetMutationActions) ||
      !isNonNegativeNumber(maxSignatureAgeSeconds) ||
      !isNonNegativeNumber(maxSingleBudgetIncreasePercent) ||
      !isNonNegativeNumber(maxCumulativeBudgetIncreasePercent24h)) {
      return undefined;
    }

    const snapshot: PolicySnapshot = {
      allowedActions: Object.freeze([...allowedActions]),
      budgetMutationActions: Object.freeze([...budgetMutationActions]),
      maxSignatureAgeSeconds,
      maxSingleBudgetIncreasePercent,
      maxCumulativeBudgetIncreasePercent24h
    };
    return Object.freeze(snapshot);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isNonNegativeNumber(value: unknown): value is number {
  return isFiniteNumber(value) && value >= 0;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0);
}

function isValidHistory(value: unknown): value is BudgetChangeEvent[] {
  return Array.isArray(value) && value.every((event) =>
    isPlainObject(event) &&
    Object.keys(event).sort().join('\0') === 'campaign_id\0percent_increase\0timestamp' &&
    typeof event.campaign_id === 'string' && event.campaign_id.length > 0 &&
    typeof event.timestamp === 'number' &&
    Number.isSafeInteger(event.timestamp) && event.timestamp > 0 &&
    event.timestamp <= MAX_SAFE_JSON_INTEGER &&
    isNonNegativeNumber(event.percent_increase)
  );
}
