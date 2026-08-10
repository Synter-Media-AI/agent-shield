import hashlib
import hmac
import json
import math
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class SynterAuditTrail:
    """Append and verify HMAC-authenticated, single-writer JSONL audit entries."""

    VERSION = "2.0.0"
    EXPECTED_KEYS = {
        "algorithm", "version", "timestamp", "agent_id", "organization_id",
        "action", "decision", "payload", "previous_digest", "digest",
    }

    def __init__(self, secret_key: str):
        if not secret_key or not secret_key.strip():
            raise ValueError("SynterAuditTrail requires a non-empty secret key.")
        self.secret_key = secret_key.encode("utf-8")

    def append_entry(
        self,
        file_path: str,
        entry: Dict[str, Any],
        timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        parent = os.path.dirname(file_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        previous_digest = None
        if os.path.exists(file_path):
            valid, violations = self.verify(file_path)
            if not valid:
                raise ValueError(f"Cannot append to an invalid audit trail: {' '.join(violations)}")
            previous_digest = self.get_checkpoint(file_path)["head_digest"]

        ts = timestamp if timestamp is not None else int(time.time())
        self._validate_new_entry(entry, ts)
        base_entry = {
            "algorithm": "hmac-sha256",
            "version": self.VERSION,
            "timestamp": ts,
            "agent_id": entry["agent_id"],
            "organization_id": entry["organization_id"],
            "action": entry["action"],
            "decision": entry["decision"],
            "payload": entry["payload"],
            "previous_digest": previous_digest,
        }
        full_entry = {**base_entry, "digest": self._compute_digest(base_entry)}

        with open(file_path, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(full_entry, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
        return full_entry

    def verify(
        self,
        file_path: str,
        expected_checkpoint: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, List[str]]:
        if not os.path.exists(file_path):
            return False, ["AUDIT_LOG_MISSING: Audit trail file does not exist."]

        try:
            lines = self._read_lines(file_path)
        except (OSError, UnicodeError, ValueError) as exc:
            return False, [f"AUDIT_LOG_MALFORMED: {exc}"]
        if not lines:
            return False, ["AUDIT_LOG_EMPTY: Audit trail contains no entries."]

        violations: List[str] = []
        if expected_checkpoint is not None and not self._is_valid_checkpoint(expected_checkpoint):
            violations.append(
                "AUDIT_CHECKPOINT_INVALID: Checkpoint contains invalid or unsupported fields."
            )
        previous_digest = None
        for index, line in enumerate(lines, start=1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                violations.append(f"AUDIT_ENTRY_INVALID_JSON: Entry {index} is not valid JSON.")
                continue

            canonical_line = json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            if line != canonical_line:
                violations.append(
                    f"AUDIT_ENTRY_NONCANONICAL: Entry {index} is not canonical writer output."
                )
                continue

            entry_violations = self._validate_stored_entry(entry, index)
            if entry_violations:
                violations.extend(entry_violations)
                continue

            digest = entry.pop("digest")
            if entry["previous_digest"] != previous_digest:
                violations.append(f"AUDIT_CHAIN_BROKEN: Entry {index} does not link to the previous digest.")
            if not hmac.compare_digest(self._compute_digest(entry), digest):
                violations.append(f"AUDIT_ENTRY_TAMPERED: Entry {index} digest mismatch.")
            previous_digest = digest

        if (
            expected_checkpoint is not None
            and self._is_valid_checkpoint(expected_checkpoint)
            and previous_digest
        ):
            if (
                expected_checkpoint.get("entry_count") != len(lines)
                or not isinstance(expected_checkpoint.get("head_digest"), str)
                or not hmac.compare_digest(expected_checkpoint["head_digest"], previous_digest)
            ):
                violations.append(
                    "AUDIT_CHECKPOINT_MISMATCH: Audit trail was truncated or replaced with a valid prefix."
                )
        return not violations, violations

    def get_checkpoint(self, file_path: str) -> Dict[str, Any]:
        valid, violations = self.verify(file_path)
        if not valid:
            raise ValueError(f"Cannot checkpoint an invalid audit trail: {' '.join(violations)}")
        lines = self._read_lines(file_path)
        final_entry = json.loads(lines[-1])
        return {"entry_count": len(lines), "head_digest": final_entry["digest"]}

    def _read_lines(self, file_path: str) -> List[str]:
        with open(file_path, "rb") as handle:
            content = handle.read().decode("utf-8", errors="strict")
        if not content:
            return []
        if not content.endswith("\n"):
            raise ValueError("Audit trail must end with a newline.")
        lines = content[:-1].split("\n")
        if any(not line for line in lines):
            raise ValueError("Audit trail must not contain blank lines.")
        return lines

    def _validate_new_entry(self, entry: Any, timestamp: int) -> None:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("agent_id"), str)
            or not entry["agent_id"]
            or not self._valid_organization_id(entry.get("organization_id"))
            or not isinstance(entry.get("action"), str)
            or not entry["action"]
            or entry.get("decision") not in {"allowed", "denied"}
            or "payload" not in entry
            or not isinstance(timestamp, int)
            or isinstance(timestamp, bool)
            or timestamp <= 0
        ):
            raise ValueError("Audit entry contains invalid required fields.")
        self._canonicalize(entry["payload"])

    def _validate_stored_entry(self, entry: Any, index: int) -> List[str]:
        if not isinstance(entry, dict):
            return [f"AUDIT_ENTRY_INVALID: Entry {index} must be an object."]
        if set(entry) != self.EXPECTED_KEYS:
            return [f"AUDIT_ENTRY_INVALID: Entry {index} contains missing or unsupported fields."]
        if (
            entry.get("algorithm") != "hmac-sha256"
            or entry.get("version") != self.VERSION
            or not isinstance(entry.get("agent_id"), str)
            or not entry["agent_id"]
            or not self._valid_organization_id(entry.get("organization_id"))
            or not isinstance(entry.get("action"), str)
            or not entry["action"]
            or entry.get("decision") not in {"allowed", "denied"}
            or not isinstance(entry.get("timestamp"), int)
            or isinstance(entry.get("timestamp"), bool)
            or entry["timestamp"] <= 0
            or (entry.get("previous_digest") is not None and not self._is_digest(entry["previous_digest"]))
            or not self._is_digest(entry.get("digest"))
        ):
            return [f"AUDIT_ENTRY_INVALID: Entry {index} has invalid field values."]
        try:
            self._canonicalize(entry["payload"])
        except (TypeError, ValueError):
            return [f"AUDIT_ENTRY_INVALID: Entry {index} payload is not supported JSON."]
        return []

    def _compute_digest(self, entry: Dict[str, Any]) -> str:
        canonical = self._canonicalize(entry)
        return hmac.new(self.secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def _canonicalize(self, value: Any) -> str:
        self._validate_json_value(value)
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def _validate_json_value(self, value: Any) -> None:
        if value is None or isinstance(value, (str, bool)):
            return
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not math.isfinite(value) or (isinstance(value, int) and abs(value) > 2**53 - 1):
                raise ValueError("Unsupported number.")
            return
        if isinstance(value, list):
            for item in value:
                self._validate_json_value(item)
            return
        if isinstance(value, dict) and all(isinstance(key, str) for key in value):
            for item in value.values():
                self._validate_json_value(item)
            return
        raise TypeError("Unsupported value.")

    @staticmethod
    def _valid_organization_id(value: Any) -> bool:
        return isinstance(value, str) or (
            isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 2**53 - 1
        )

    @staticmethod
    def _is_digest(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdefABCDEF" for character in value)
        )

    @classmethod
    def _is_valid_checkpoint(cls, value: Any) -> bool:
        return (
            isinstance(value, dict)
            and set(value) == {"entry_count", "head_digest"}
            and type(value.get("entry_count")) is int
            and value["entry_count"] > 0
            and cls._is_digest(value.get("head_digest"))
        )
