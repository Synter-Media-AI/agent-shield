import { SynterAgentSigner, type SignedPayloadEnvelope } from './signer.js';

export interface BudgetMutationPayload {
  action: string;
  campaignId: string;
  currentBudget: number;
  proposedBudget: number;
}

export interface BudgetChangeEvent {
  campaignId: string;
  timestamp: number;
  percentIncrease: number;
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

const DEFAULT_POLICY: Required<ExecutionPolicy> = {
  allowedActions: ['*'],
  budgetMutationActions: ['UNCAP_BUDGET', 'UPDATE_BUDGET', 'SET_BUDGET', 'INCREASE_BUDGET'],
  maxSignatureAgeSeconds: 300,
  maxSingleBudgetIncreasePercent: 30,
  maxCumulativeBudgetIncreasePercent24h: 30
};

export class SynterExecutionGuard {
  private readonly signer: SynterAgentSigner;
  private readonly policy: Required<ExecutionPolicy>;

  constructor(secretKey: string, policy: ExecutionPolicy = {}) {
    this.signer = new SynterAgentSigner(secretKey);
    this.validateRawPolicy(policy);
    this.policy = {
      ...DEFAULT_POLICY,
      ...policy,
      allowedActions: [...new Set(policy.allowedActions ?? DEFAULT_POLICY.allowedActions)],
      budgetMutationActions: [...new Set(policy.budgetMutationActions ?? DEFAULT_POLICY.budgetMutationActions)]
    };
    this.validatePolicy();
  }

  /**
   * Verifies a signed action envelope, then evaluates simple spend safety rules
   * before a runtime forwards the action to an external execution engine.
   */
  public authorize<T extends Record<string, unknown>>(
    envelope: SignedPayloadEnvelope<T>,
    context: ExecutionPolicyContext = {}
  ): ExecutionDecision {
    const verification = this.signer.verifySignature(envelope, this.policy.maxSignatureAgeSeconds);
    if (!verification.valid) {
      return {
        allowed: false,
        violations: [verification.error ?? 'SIGNATURE_INVALID']
      };
    }

    const violations: string[] = [];
    const action = this.extractAction(envelope.payload);

    if (!this.policy.allowedActions.includes('*') && !this.policy.allowedActions.includes(action)) {
      violations.push(`ACTION_NOT_ALLOWED: Action '${action}' is not permitted by policy.`);
    }

    const budgetDecision = this.evaluateBudgetMutation(envelope.payload, context?.recentBudgetChanges);
    violations.push(...budgetDecision.violations);

    return {
      allowed: violations.length === 0,
      violations,
      budgetIncreasePercent: budgetDecision.budgetIncreasePercent
    };
  }

  private extractAction(payload: Record<string, unknown>): string {
    return typeof payload.action === 'string' ? payload.action : 'UNKNOWN_ACTION';
  }

  private evaluateBudgetMutation(
    payload: Record<string, unknown>,
    recentBudgetChanges: unknown
  ): { violations: string[]; budgetIncreasePercent?: number } {
    if (!this.looksLikeBudgetMutation(payload)) {
      return { violations: [] };
    }

    if (!this.isBudgetMutationPayload(payload)) {
      return {
        violations: [
          'INVALID_BUDGET_MUTATION: Budget actions require a non-empty campaignId and finite currentBudget and proposedBudget values.'
        ]
      };
    }

    if (payload.currentBudget <= 0) {
      return {
        violations: ['INVALID_BUDGET_BASELINE: currentBudget must be greater than zero for policy enforcement.']
      };
    }

    if (payload.proposedBudget < 0) {
      return { violations: ['INVALID_BUDGET_MUTATION: proposedBudget must be greater than or equal to zero.'] };
    }

    if (payload.proposedBudget <= payload.currentBudget) {
      return { violations: [], budgetIncreasePercent: 0 };
    }

    const budgetIncreasePercent = ((payload.proposedBudget - payload.currentBudget) / payload.currentBudget) * 100;
    const violations: string[] = [];

    if (budgetIncreasePercent > this.policy.maxSingleBudgetIncreasePercent) {
      violations.push(
        `BUDGET_STEP_CAP_EXCEEDED: Proposed increase of ${budgetIncreasePercent.toFixed(2)}% exceeds the ${this.policy.maxSingleBudgetIncreasePercent}% single-action cap.`
      );
    }

    if (!Array.isArray(recentBudgetChanges)) {
      violations.push('INVALID_BUDGET_HISTORY: recentBudgetChanges must be supplied as an array for budget increases.');
      return { violations, budgetIncreasePercent };
    }
    if (recentBudgetChanges.some((change) => !this.isValidBudgetChangeEvent(change))) {
      violations.push('INVALID_BUDGET_HISTORY: recentBudgetChanges contains a malformed event.');
      return { violations, budgetIncreasePercent };
    }

    const windowStart = Math.floor(Date.now() / 1000) - 24 * 60 * 60;
    const recentIncrease = recentBudgetChanges
      .filter((change) => change.campaignId === payload.campaignId && change.timestamp >= windowStart)
      .reduce((sum, change) => sum + change.percentIncrease, 0);
    const cumulativeIncrease = recentIncrease + budgetIncreasePercent;

    if (cumulativeIncrease > this.policy.maxCumulativeBudgetIncreasePercent24h) {
      violations.push(
        `BUDGET_24H_CAP_EXCEEDED: Proposed cumulative increase of ${cumulativeIncrease.toFixed(2)}% exceeds the ${this.policy.maxCumulativeBudgetIncreasePercent24h}% 24-hour cap.`
      );
    }

    return { violations, budgetIncreasePercent };
  }

  private isBudgetMutationPayload(payload: unknown): payload is BudgetMutationPayload {
    if (!payload || typeof payload !== 'object') {
      return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
      typeof candidate.action === 'string' &&
      typeof candidate.campaignId === 'string' &&
      candidate.campaignId.length > 0 &&
      typeof candidate.currentBudget === 'number' &&
      Number.isFinite(candidate.currentBudget) &&
      typeof candidate.proposedBudget === 'number' &&
      Number.isFinite(candidate.proposedBudget)
    );
  }

  private looksLikeBudgetMutation(payload: Record<string, unknown>): boolean {
    return (
      (typeof payload.action === 'string' && /BUDGET/i.test(payload.action)) ||
      (typeof payload.action === 'string' && this.policy.budgetMutationActions.includes(payload.action)) ||
      'currentBudget' in payload ||
      'proposedBudget' in payload
    );
  }

  private isValidBudgetChangeEvent(change: unknown): change is BudgetChangeEvent {
    if (!change || typeof change !== 'object' || Array.isArray(change)) {
      return false;
    }
    const candidate = change as Record<string, unknown>;
    return (
      typeof candidate.campaignId === 'string' &&
      candidate.campaignId.length > 0 &&
      typeof candidate.timestamp === 'number' &&
      Number.isSafeInteger(candidate.timestamp) &&
      candidate.timestamp > 0 &&
      typeof candidate.percentIncrease === 'number' &&
      Number.isFinite(candidate.percentIncrease) &&
      candidate.percentIncrease >= 0
    );
  }

  private validatePolicy(): void {
    if (
      !Array.isArray(this.policy.allowedActions) ||
      this.policy.allowedActions.some((action) => typeof action !== 'string' || action.length === 0)
    ) {
      throw new Error("SynterExecutionGuard policy field 'allowedActions' must contain only non-empty strings.");
    }
    if (this.policy.budgetMutationActions.some((action) => typeof action !== 'string' || action.length === 0)) {
      throw new Error("SynterExecutionGuard policy field 'budgetMutationActions' must contain only non-empty strings.");
    }

    for (const [key, value] of Object.entries({
      maxSignatureAgeSeconds: this.policy.maxSignatureAgeSeconds,
      maxSingleBudgetIncreasePercent: this.policy.maxSingleBudgetIncreasePercent,
      maxCumulativeBudgetIncreasePercent24h: this.policy.maxCumulativeBudgetIncreasePercent24h
    })) {
      if (!Number.isFinite(value) || value < 0) {
        throw new Error(`SynterExecutionGuard policy field '${key}' must be a finite number greater than or equal to zero.`);
      }
    }
  }

  private validateRawPolicy(policy: ExecutionPolicy): void {
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
      throw new Error('SynterExecutionGuard policy must be an object.');
    }
    const supportedKeys = new Set([
      'allowedActions', 'budgetMutationActions', 'maxSignatureAgeSeconds',
      'maxSingleBudgetIncreasePercent', 'maxCumulativeBudgetIncreasePercent24h'
    ]);
    if (Object.keys(policy).some((key) => !supportedKeys.has(key))) {
      throw new Error('SynterExecutionGuard policy contains an unsupported field.');
    }
    for (const [key, actions] of Object.entries({
      allowedActions: policy.allowedActions,
      budgetMutationActions: policy.budgetMutationActions
    })) {
      if (actions !== undefined && (
        !Array.isArray(actions) || actions.some((action) => typeof action !== 'string' || action.length === 0)
      )) {
        throw new Error(`SynterExecutionGuard policy field '${key}' must contain only non-empty strings.`);
      }
    }
  }
}
