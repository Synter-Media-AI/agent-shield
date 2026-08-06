import math
import time
from typing import Any, Dict, List, Optional, Tuple
from ._canonical import MAX_SAFE_JSON_INTEGER
from .signer import SynterAgentSigner

_UNSET = object()
DEFAULTS = {
    "allowed_actions": [],
    "budget_mutation_actions": ["SET_BUDGET", "UNCAP_BUDGET", "UPDATE_BUDGET"],
    "max_signature_age_seconds": 300,
    "max_single_budget_increase_percent": 30,
    "max_cumulative_budget_increase_percent_24h": 30,
}


class SynterExecutionGuard:
    def __init__(self, secret_key: str, policy: Any = _UNSET):
        self.signer = SynterAgentSigner(secret_key)
        if policy is _UNSET:
            policy = {}
        if not isinstance(policy, dict):
            self.policy = None
            return
        if any(key not in DEFAULTS for key in policy):
            self.policy = None
            return
        allowed_actions = policy.get("allowed_actions", DEFAULTS["allowed_actions"])
        budget_actions = policy.get("budget_mutation_actions", DEFAULTS["budget_mutation_actions"])
        self.policy = {**DEFAULTS, **policy}
        if isinstance(allowed_actions, list):
            self.policy["allowed_actions"] = list(allowed_actions)
        if isinstance(budget_actions, list):
            self.policy["budget_mutation_actions"] = list(budget_actions)

    def authorize(
        self,
        envelope: Dict[str, Any],
        recent_budget_changes: Any = _UNSET,
    ) -> Tuple[bool, List[str], Optional[float]]:
        if not self._valid_policy():
            return False, ["INVALID_POLICY: Policy configuration is malformed."], None
        valid, error = self.signer.verify_signature(envelope, self.policy["max_signature_age_seconds"])
        if not valid:
            return False, [error or "SIGNATURE_INVALID"], None
        payload = envelope.get("payload")
        action = payload.get("action") if isinstance(payload, dict) else None
        if not isinstance(action, str) or not action:
            return False, ["INVALID_ACTION: action must be a non-empty string."], None
        violations = []
        if self.policy["allowed_actions"] and action not in self.policy["allowed_actions"]:
            violations.append(f"ACTION_NOT_ALLOWED: Action '{action}' is not permitted by policy.")
        if action not in self.policy["budget_mutation_actions"]:
            return not violations, violations, None
        campaign = payload.get("campaign_id")
        current = payload.get("current_budget")
        proposed = payload.get("proposed_budget")
        if (not isinstance(campaign, str) or not campaign or not self._finite_number(current) or current <= 0
                or not self._finite_number(proposed) or proposed < 0):
            violations.append("INVALID_BUDGET_MUTATION: campaign_id, current_budget > 0, and proposed_budget >= 0 are required.")
            return False, violations, None
        increase = ((proposed - current) / current) * 100 if proposed > current else 0.0
        if increase > self.policy["max_single_budget_increase_percent"]:
            violations.append("BUDGET_STEP_CAP_EXCEEDED: Proposed increase exceeds the single-action cap.")
        history = [] if recent_budget_changes is _UNSET else recent_budget_changes
        if not isinstance(history, list) or any(not self._valid_history_event(h) for h in history):
            violations.append("INVALID_BUDGET_HISTORY: Recent budget history is malformed.")
            return False, violations, increase
        since = int(time.time()) - 86400
        cumulative = increase + sum(h["percent_increase"] for h in history if h["campaign_id"] == campaign and h["timestamp"] >= since)
        if cumulative > self.policy["max_cumulative_budget_increase_percent_24h"]:
            violations.append("BUDGET_24H_CAP_EXCEEDED: Proposed cumulative increase exceeds the 24-hour cap.")
        return not violations, violations, increase

    @staticmethod
    def _finite_number(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if isinstance(value, int):
            return abs(value) <= MAX_SAFE_JSON_INTEGER
        return math.isfinite(value)

    def _valid_policy(self):
        if not isinstance(self.policy, dict):
            return False
        arrays = (self.policy.get("allowed_actions"), self.policy.get("budget_mutation_actions"))
        numbers = (self.policy.get("max_signature_age_seconds"), self.policy.get("max_single_budget_increase_percent"),
                   self.policy.get("max_cumulative_budget_increase_percent_24h"))
        return all(isinstance(a, list) and all(isinstance(x, str) and x for x in a) for a in arrays) and \
            all(self._finite_number(x) and x >= 0 for x in numbers)

    @classmethod
    def _valid_history_event(cls, event):
        return (
            isinstance(event, dict)
            and set(event) == {"campaign_id", "timestamp", "percent_increase"}
            and isinstance(event.get("campaign_id"), str)
            and bool(event["campaign_id"])
            and not isinstance(event.get("timestamp"), bool)
            and isinstance(event["timestamp"], int)
            and 0 < event["timestamp"] <= MAX_SAFE_JSON_INTEGER
            and cls._finite_number(event.get("percent_increase"))
            and event["percent_increase"] >= 0
        )
