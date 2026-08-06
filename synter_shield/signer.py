import hmac
import hashlib
import math
import time
from typing import Any, Dict, Optional, Tuple

import rfc8785

from ._canonical import MAX_SAFE_JSON_INTEGER, canonical_json, secret_bytes

DOMAIN = b"agent-shield/envelope/v1\0"

class SynterAgentSigner:
    """
    Cryptographic digital signature helper for Synter autonomous agents,
    campaign plans, and tool execution payloads (Python implementation).
    """
    def __init__(self, secret_key: str):
        self.secret_key = secret_bytes(secret_key)

    def sign_payload(
        self,
        agent_id: str,
        organization_id: str,
        payload: Dict[str, Any],
        timestamp: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Cryptographically signs an agent payload or tool call execution intent.
        """
        ts = timestamp if timestamp is not None else int(time.time())
        unsigned = self._unsigned(agent_id, organization_id, ts, payload)
        message = DOMAIN + canonical_json(unsigned)

        signature = hmac.new(
            self.secret_key,
            message,
            hashlib.sha256
        ).hexdigest()

        return {
            **unsigned,
            "signature": signature
        }

    def verify_signature(
        self,
        envelope: Dict[str, Any],
        max_age_seconds: int = 300
    ) -> Tuple[bool, Optional[str]]:
        """
        Verifies payload integrity and timestamp freshness. The host must
        separately and atomically deduplicate accepted envelopes.
        """
        if not isinstance(envelope, dict):
            return False, "INVALID_ENVELOPE: Envelope is not valid Agent Shield JSON."
        if set(envelope) != {
            "schema_version", "algorithm", "agent_id", "organization_id",
            "timestamp", "payload", "signature",
        }:
            return False, "INVALID_ENVELOPE: Envelope is not valid Agent Shield JSON."
        agent_id = envelope.get("agent_id")
        org_id = envelope.get("organization_id")
        timestamp = envelope.get("timestamp")
        payload = envelope.get("payload")
        signature = envelope.get("signature")

        valid_max_age = (
            not isinstance(max_age_seconds, bool)
            and isinstance(max_age_seconds, (int, float))
            and (not isinstance(max_age_seconds, int) or abs(max_age_seconds) <= MAX_SAFE_JSON_INTEGER)
        )
        if valid_max_age and isinstance(max_age_seconds, float):
            valid_max_age = math.isfinite(max_age_seconds)

        if (
            envelope.get("schema_version") != "1.0"
            or envelope.get("algorithm") != "hmac-sha256"
            or not isinstance(signature, str)
            or len(signature) != 64
            or any(c not in "0123456789abcdef" for c in signature)
            or not valid_max_age
            or max_age_seconds < 0
        ):
            return False, "INVALID_ENVELOPE: Envelope is not valid Agent Shield JSON."

        try:
            unsigned = self._unsigned(agent_id, org_id, timestamp, payload)
        except (TypeError, ValueError, UnicodeError, rfc8785.CanonicalizationError):
            return False, "INVALID_ENVELOPE: Envelope is not valid Agent Shield JSON."

        current_ts = int(time.time())
        if timestamp < current_ts - max_age_seconds or timestamp > current_ts + 30:
            return False, "STALE_OR_FUTURE_ENVELOPE: Timestamp outside acceptable window."

        message = DOMAIN + canonical_json(unsigned)

        expected_sig = hmac.new(
            self.secret_key,
            message,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, signature):
            return False, "SIGNATURE_MISMATCH: Payload has been tampered with or key is invalid."

        return True, None

    def _unsigned(self, agent_id: str, organization_id: str, timestamp: int, payload: Any) -> Dict[str, Any]:
        if (not isinstance(agent_id, str) or not agent_id or not isinstance(organization_id, str)
                or not organization_id or isinstance(timestamp, bool) or not isinstance(timestamp, int)
                or timestamp <= 0 or timestamp > MAX_SAFE_JSON_INTEGER or not isinstance(payload, dict)):
            raise ValueError("Invalid envelope fields")
        canonical_json(payload)
        return {"schema_version": "1.0", "algorithm": "hmac-sha256", "agent_id": agent_id,
                "organization_id": organization_id, "timestamp": timestamp, "payload": payload}
