import time
from typing import Any, Dict, List, Optional, Tuple

from .signer import SynterAgentSigner


class SynterExecutionGuard:
    """
    Verifies signed envelopes and applies simple spend safety policies before
    a runtime forwards actions to an external execution engine.
    """

    def __init__(self, secret_key: str, policy: Optional[Dict[str, Any]] = None):
        self.signer = SynterAgentSigner(secret_key)
        self.policy = {
            "allowed_actions": [],
            "max_signature_age_seconds": 300,
            "max_single_budget_increase_percent": 30,
            "max_cumulative_budget_increase_percent_24h": 30,
        }
        if policy:
            self.policy.update(policy)

    def authorize(
        self,
        envelope: Dict[str, Any],
        recent_budget_changes: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, List[str], Optional[float]]:
        valid, err = self.signer.verify_signature(
            envelope,
            max_age_seconds=self.policy["max_signature_age_seconds"],
        )
        if not valid:
            return False, [err or "SIGNATURE_INVALID"], None

        violations: List[str] = []
        payload = envelope.get("payload", {})
        action = payload.get("action", "UNKNOWN_ACTION")
        allowed_actions = self.policy.get("allowed_actions", [])

        if allowed_actions and action not in allowed_actions:
            violations.append(f"ACTION_NOT_ALLOWED: Action '{action}' is not permitted by policy.")

        budget_increase_percent = None
        if self._is_budget_mutation_payload(payload):
            current_budget = payload["current_budget"]
            proposed_budget = payload["proposed_budget"]
            campaign_id = payload["campaign_id"]

            if current_budget <= 0:
                violations.append(
                    "INVALID_BUDGET_BASELINE: current_budget must be greater than zero for policy enforcement."
                )
            elif proposed_budget > current_budget:
                budget_increase_percent = ((proposed_budget - current_budget) / current_budget) * 100.0
                if budget_increase_percent > self.policy["max_single_budget_increase_percent"]:
                    violations.append(
                        "BUDGET_STEP_CAP_EXCEEDED: "
                        f"Proposed increase of {budget_increase_percent:.2f}% exceeds the "
                        f"{self.policy['max_single_budget_increase_percent']}% single-action cap."
                    )

                window_start = int(time.time()) - 24 * 60 * 60
                recent_increase = sum(
                    float(change.get("percent_increase", 0))
                    for change in (recent_budget_changes or [])
                    if change.get("campaign_id") == campaign_id and int(change.get("timestamp", 0)) >= window_start
                )
                cumulative_increase = recent_increase + budget_increase_percent
                if cumulative_increase > self.policy["max_cumulative_budget_increase_percent_24h"]:
                    violations.append(
                        "BUDGET_24H_CAP_EXCEEDED: "
                        f"Proposed cumulative increase of {cumulative_increase:.2f}% exceeds the "
                        f"{self.policy['max_cumulative_budget_increase_percent_24h']}% 24-hour cap."
                    )
            else:
                budget_increase_percent = 0.0

        return len(violations) == 0, violations, budget_increase_percent

    def _is_budget_mutation_payload(self, payload: Dict[str, Any]) -> bool:
        return all(
            key in payload
            for key in ["action", "campaign_id", "current_budget", "proposed_budget"]
        )
