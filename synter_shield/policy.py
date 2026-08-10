import time
import math
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
            "allowed_actions": ["*"],
            "budget_mutation_actions": [
                "UNCAP_BUDGET", "UPDATE_BUDGET", "SET_BUDGET", "INCREASE_BUDGET"
            ],
            "max_signature_age_seconds": 300,
            "max_single_budget_increase_percent": 30,
            "max_cumulative_budget_increase_percent_24h": 30,
        }
        if policy is not None:
            self._validate_raw_policy(policy)
            self.policy.update(policy)
        allowed_actions = self.policy.get("allowed_actions")
        if isinstance(allowed_actions, list):
            self.policy["allowed_actions"] = list(dict.fromkeys(allowed_actions))
        budget_actions = self.policy.get("budget_mutation_actions")
        if isinstance(budget_actions, list):
            self.policy["budget_mutation_actions"] = list(dict.fromkeys(budget_actions))
        self._validate_policy()

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

        if "*" not in allowed_actions and action not in allowed_actions:
            violations.append(f"ACTION_NOT_ALLOWED: Action '{action}' is not permitted by policy.")

        budget_increase_percent = None
        if self._looks_like_budget_mutation(payload) and not self._is_budget_mutation_payload(payload):
            violations.append(
                "INVALID_BUDGET_MUTATION: Budget actions require a non-empty campaign_id and "
                "finite current_budget and proposed_budget values."
            )
        elif self._is_budget_mutation_payload(payload):
            current_budget = payload["current_budget"]
            proposed_budget = payload["proposed_budget"]
            campaign_id = payload["campaign_id"]

            if current_budget <= 0:
                violations.append(
                    "INVALID_BUDGET_BASELINE: current_budget must be greater than zero for policy enforcement."
                )
            elif proposed_budget < 0:
                violations.append(
                    "INVALID_BUDGET_MUTATION: proposed_budget must be greater than or equal to zero."
                )
            elif proposed_budget > current_budget:
                budget_increase_percent = ((proposed_budget - current_budget) / current_budget) * 100.0
                if budget_increase_percent > self.policy["max_single_budget_increase_percent"]:
                    violations.append(
                        "BUDGET_STEP_CAP_EXCEEDED: "
                        f"Proposed increase of {budget_increase_percent:.2f}% exceeds the "
                        f"{self.policy['max_single_budget_increase_percent']}% single-action cap."
                    )

                if not isinstance(recent_budget_changes, list):
                    violations.append(
                        "INVALID_BUDGET_HISTORY: recent_budget_changes must be supplied as a list "
                        "for budget increases."
                    )
                    return False, violations, budget_increase_percent
                window_start = int(time.time()) - 24 * 60 * 60
                changes = recent_budget_changes
                if any(not self._is_valid_budget_change_event(change) for change in changes):
                    violations.append(
                        "INVALID_BUDGET_HISTORY: recent_budget_changes contains a malformed event."
                    )
                    return False, violations, budget_increase_percent
                recent_increase = sum(
                    change["percent_increase"]
                    for change in changes
                    if change["campaign_id"] == campaign_id and change["timestamp"] >= window_start
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
        return (
            isinstance(payload, dict)
            and isinstance(payload.get("action"), str)
            and isinstance(payload.get("campaign_id"), str)
            and bool(payload.get("campaign_id"))
            and self._is_finite_number(payload.get("current_budget"))
            and self._is_finite_number(payload.get("proposed_budget"))
        )

    def _looks_like_budget_mutation(self, payload: Dict[str, Any]) -> bool:
        if not isinstance(payload, dict):
            return False
        action = payload.get("action")
        return (
            (isinstance(action, str) and "BUDGET" in action.upper())
            or (isinstance(action, str) and action in self.policy["budget_mutation_actions"])
            or any(key in payload for key in ("current_budget", "proposed_budget"))
        )

    def _is_valid_budget_change_event(self, change: Any) -> bool:
        return (
            isinstance(change, dict)
            and isinstance(change.get("campaign_id"), str)
            and bool(change.get("campaign_id"))
            and isinstance(change.get("timestamp"), int)
            and not isinstance(change.get("timestamp"), bool)
            and change["timestamp"] > 0
            and self._is_finite_number(change.get("percent_increase"))
            and change["percent_increase"] >= 0
        )

    def _validate_policy(self) -> None:
        allowed_actions = self.policy.get("allowed_actions")
        if (
            not isinstance(allowed_actions, list)
            or any(not isinstance(action, str) or not action for action in allowed_actions)
        ):
            raise ValueError(
                "SynterExecutionGuard policy field 'allowed_actions' must contain only non-empty strings."
            )

        budget_actions = self.policy.get("budget_mutation_actions")
        if (
            not isinstance(budget_actions, list)
            or any(not isinstance(action, str) or not action for action in budget_actions)
        ):
            raise ValueError(
                "SynterExecutionGuard policy field 'budget_mutation_actions' must contain only non-empty strings."
            )

        for key in [
            "max_signature_age_seconds",
            "max_single_budget_increase_percent",
            "max_cumulative_budget_increase_percent_24h",
        ]:
            value = self.policy[key]
            if not self._is_finite_number(value) or value < 0:
                raise ValueError(
                    f"SynterExecutionGuard policy field '{key}' must be a finite number greater than or equal to zero."
                )

    @staticmethod
    def _validate_raw_policy(policy: Any) -> None:
        if not isinstance(policy, dict):
            raise ValueError("SynterExecutionGuard policy must be an object.")
        supported_keys = {
            "allowed_actions", "budget_mutation_actions", "max_signature_age_seconds",
            "max_single_budget_increase_percent", "max_cumulative_budget_increase_percent_24h",
        }
        if any(key not in supported_keys for key in policy):
            raise ValueError("SynterExecutionGuard policy contains an unsupported field.")
        for key in ("allowed_actions", "budget_mutation_actions"):
            actions = policy.get(key)
            if actions is not None and (
                not isinstance(actions, list)
                or any(not isinstance(action, str) or not action for action in actions)
            ):
                raise ValueError(
                    f"SynterExecutionGuard policy field '{key}' must contain only non-empty strings."
                )

    @staticmethod
    def _is_finite_number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
