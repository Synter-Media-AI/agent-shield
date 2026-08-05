import hmac
import hashlib
import json
import time
from typing import Any, Dict, Optional, Tuple, Union

class SynterAgentSigner:
    """
    Cryptographic digital signature helper for Synter autonomous agents,
    campaign plans, and tool execution payloads (Python implementation).
    """
    def __init__(self, secret_key: str):
        if not secret_key or not secret_key.strip():
            raise ValueError("SynterAgentSigner requires a non-empty secret key.")
        self.secret_key = secret_key.encode('utf-8')

    def sign_payload(
        self,
        agent_id: str,
        organization_id: Union[int, str],
        payload: Dict[str, Any],
        timestamp: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Cryptographically signs an agent payload or tool call execution intent.
        """
        ts = timestamp if timestamp is not None else int(time.time())
        canonical_data = json.dumps(payload, sort_keys=True)
        message = f"{agent_id}:{organization_id}:{ts}:{canonical_data}"

        signature = hmac.new(
            self.secret_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return {
            "agent_id": agent_id,
            "organization_id": organization_id,
            "timestamp": ts,
            "payload": payload,
            "signature": signature
        }

    def verify_signature(
        self,
        envelope: Dict[str, Any],
        max_age_seconds: int = 300
    ) -> Tuple[bool, Optional[str]]:
        """
        Verifies a signed agent envelope for payload integrity and replay prevention.
        """
        agent_id = envelope.get("agent_id")
        org_id = envelope.get("organization_id")
        timestamp = envelope.get("timestamp")
        payload = envelope.get("payload")
        signature = envelope.get("signature")

        if not all([agent_id, org_id, timestamp, payload, signature]):
            return False, "INVALID_ENVELOPE: Missing required fields."

        current_ts = int(time.time())
        if abs(current_ts - timestamp) > max_age_seconds:
            return False, "REPLAY_ATTACK_PREVENTED: Timestamp outside acceptable window."

        canonical_data = json.dumps(payload, sort_keys=True)
        message = f"{agent_id}:{org_id}:{timestamp}:{canonical_data}"

        expected_sig = hmac.new(
            self.secret_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, signature):
            return False, "SIGNATURE_MISMATCH: Payload has been tampered with or key is invalid."

        return True, None
