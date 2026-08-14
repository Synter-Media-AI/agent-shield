import hmac
import hashlib
import json
import math
import struct
import time
from typing import Any, Dict, Optional, Tuple, Union

class SynterAgentSigner:
    """
    Cryptographic digital signature helper for Synter autonomous agents,
    campaign plans, and tool execution payloads (Python implementation).
    """
    SIGNATURE_PROTOCOL = "synter.intent.v2"
    SIGNATURE_HEX_LENGTH = 64
    MAX_CLOCK_SKEW_SECONDS = 30

    def __init__(self, secret_key: str):
        if not isinstance(secret_key, str) or len(secret_key.encode("utf-8")) < 32:
            raise ValueError("SynterAgentSigner requires a secret key containing at least 32 UTF-8 bytes.")
        self._validate_unicode(secret_key)
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
        self._validate_signing_inputs(agent_id, organization_id, payload, ts)
        message = self._build_signature_message(agent_id, organization_id, ts, payload)

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
        if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds < 0:
            return False, "INVALID_MAX_AGE: max_age_seconds must be a finite nonnegative integer."
        if not isinstance(envelope, dict):
            return False, "INVALID_ENVELOPE: Envelope must be an object."
        if set(envelope) != {"agent_id", "organization_id", "timestamp", "payload", "signature"}:
            return False, "INVALID_ENVELOPE: Envelope contains missing or unsupported fields."

        agent_id = envelope.get("agent_id")
        org_id = envelope.get("organization_id")
        timestamp = envelope.get("timestamp")
        payload = envelope.get("payload")
        signature = envelope.get("signature")

        if (
            not isinstance(agent_id, str)
            or not agent_id
            or not self._is_valid_organization_id(org_id)
            or not isinstance(timestamp, int)
            or isinstance(timestamp, bool)
            or timestamp <= 0
            or timestamp > 2**53 - 1
            or payload is None
            or not isinstance(signature, str)
            or len(signature) != self.SIGNATURE_HEX_LENGTH
            or any(char not in "0123456789abcdefABCDEF" for char in signature)
        ):
            return False, "INVALID_ENVELOPE: Missing required fields."

        try:
            self._encode_value({
                "agentId": agent_id,
                "organizationId": org_id,
                "payload": payload,
            })
        except (TypeError, ValueError, OverflowError, UnicodeError):
            return False, "INVALID_ENVELOPE: Payload must contain only supported JSON values."

        current_ts = int(time.time())
        if timestamp > current_ts + self.MAX_CLOCK_SKEW_SECONDS:
            return False, "FUTURE_TIMESTAMP_REJECTED: Timestamp is too far in the future."

        if current_ts - timestamp > max_age_seconds:
            return False, "REPLAY_ATTACK_PREVENTED: Timestamp outside acceptable window."

        try:
            message = self._build_signature_message(agent_id, org_id, timestamp, payload)
            encoded_message = message.encode('utf-8')
        except (TypeError, ValueError, OverflowError, UnicodeError):
            return False, "INVALID_ENVELOPE: Payload contains unsupported values."

        expected_sig = hmac.new(
            self.secret_key,
            encoded_message,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, signature):
            return False, "SIGNATURE_MISMATCH: Payload has been tampered with or key is invalid."

        return True, None

    def _build_signature_message(
        self,
        agent_id: str,
        organization_id: Union[int, str],
        timestamp: int,
        payload: Any,
    ) -> str:
        encoded = self._encode_value({
            "protocol": self.SIGNATURE_PROTOCOL,
            "agentId": agent_id,
            "organizationId": organization_id,
            "timestamp": timestamp,
            "payload": payload,
        })
        return json.dumps(encoded, ensure_ascii=False, separators=(",", ":"))

    def _encode_value(self, value: Any) -> Any:
        if value is None:
            return ["null"]
        if isinstance(value, bool):
            return ["boolean", value]
        if isinstance(value, str):
            self._validate_unicode(value)
            return ["string", value]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                numeric_value = float(value)
            except OverflowError as exc:
                raise ValueError("Unsupported number.") from exc
            if not math.isfinite(numeric_value):
                raise ValueError("Unsupported number.")
            if isinstance(value, int) and int(numeric_value) != value:
                raise ValueError("Integer is not exactly representable as a binary64 number.")
            return ["number", struct.pack(">d", numeric_value).hex()]
        if isinstance(value, list):
            return ["array", [self._encode_value(entry) for entry in value]]
        if isinstance(value, dict):
            if not all(isinstance(key, str) for key in value):
                raise TypeError("Object keys must be strings.")
            entries = [
                [key, self._encode_value(value[key])]
                for key in sorted(value, key=lambda item: item.encode("utf-8"))
            ]
            return ["object", entries]
        raise TypeError("Unsupported value.")

    def _validate_signing_inputs(
        self,
        agent_id: str,
        organization_id: Union[int, str],
        payload: Any,
        timestamp: int,
    ) -> None:
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError("agent_id must be a non-empty string.")
        if not self._is_valid_organization_id(organization_id):
            raise ValueError("organization_id must be a string or safe integer.")
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp <= 0 or timestamp > 2**53 - 1:
            raise ValueError("timestamp must be a positive safe integer.")
        if payload is None:
            raise ValueError("payload must not be null.")
        self._encode_value({
            "agentId": agent_id,
            "organizationId": organization_id,
            "payload": payload,
        })

    @staticmethod
    def _is_valid_organization_id(value: Any) -> bool:
        return isinstance(value, str) or (
            isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 2**53 - 1
        )

    @staticmethod
    def _validate_unicode(value: str) -> None:
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("Strings must contain valid Unicode scalar values.")
