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
  allowedActions: [],
  maxSignatureAgeSeconds: 300,
  maxSingleBudgetIncreasePercent: 30,
  maxCumulativeBudgetIncreasePercent24h: 30
};

export class SynterExecutionGuard {
  private readonly signer: SynterAgentSigner;
  private readonly policy: Required<ExecutionPolicy>;

  constructor(secretKey: string, policy: ExecutionPolicy = {}) {
    this.signer = new SynterAgentSigner(secretKey);
    this.policy = {
      ...DEFAULT_POLICY,
      ...policy,
      allowedActions: policy.allowedActions ?? DEFAULT_POLICY.allowedActions
    };
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

    if (this.policy.allowedActions.length > 0 && !this.policy.allowedActions.includes(action)) {
      violations.push(`ACTION_NOT_ALLOWED: Action '${action}' is not permitted by policy.`);
    }

    const budgetDecision = this.evaluateBudgetMutation(envelope.payload, context.recentBudgetChanges ?? []);
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
    recentBudgetChanges: BudgetChangeEvent[]
  ): { violations: string[]; budgetIncreasePercent?: number } {
    if (!this.isBudgetMutationPayload(payload)) {
      return { violations: [] };
    }

    if (payload.currentBudget <= 0) {
      return {
        violations: ['INVALID_BUDGET_BASELINE: currentBudget must be greater than zero for policy enforcement.']
      };
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
      typeof candidate.currentBudget === 'number' &&
      typeof candidate.proposedBudget === 'number'
    );
  }
}
