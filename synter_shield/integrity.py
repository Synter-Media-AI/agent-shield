import hashlib
import hmac
import json
import os
from typing import Dict, List, Tuple


class SynterIntegrityGuard:
    """
    Generates and verifies signed manifests for agent skill directories.
    """

    def __init__(self, secret_key: str):
        if not secret_key or not secret_key.strip():
            raise ValueError("SynterIntegrityGuard requires a non-empty secret key.")
        self.secret_key = secret_key.encode("utf-8")

    def generate_manifest(self, directory_path: str) -> Dict[str, object]:
        file_hashes = self._collect_file_hashes(directory_path)
        canonical_manifest = json.dumps(file_hashes, sort_keys=True)
        signature = hmac.new(
            self.secret_key,
            canonical_manifest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            "version": "1.0.0",
            "file_count": len(file_hashes),
            "file_hashes": file_hashes,
            "signature": signature,
        }

    def verify_integrity(self, directory_path: str, manifest: Dict[str, object]) -> Tuple[bool, List[str]]:
        file_hashes = manifest.get("file_hashes", {})
        signature = manifest.get("signature", "")
        canonical_manifest = json.dumps(file_hashes, sort_keys=True)
        expected_signature = hmac.new(
            self.secret_key,
            canonical_manifest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if expected_signature != signature:
            return False, ["MANIFEST_SIGNATURE_INVALID: Manifest has been modified or forged!"]

        current_file_hashes = self._collect_file_hashes(directory_path)
        violations: List[str] = []

        for rel_path, expected_hash in file_hashes.items():
            current_hash = current_file_hashes.get(rel_path)
            if current_hash is None:
                violations.append(f"MISSING_FILE: File '{rel_path}' was deleted or moved.")
                continue

            if current_hash != expected_hash:
                violations.append(f"TAMPERED_FILE: File '{rel_path}' has been modified or injected with untrusted code!")

        for rel_path in current_file_hashes:
            if rel_path not in file_hashes:
                violations.append(f"UNEXPECTED_FILE: File '{rel_path}' was added after compilation.")

        return len(violations) == 0, violations

    def list_protected_files(self, directory_path: str) -> List[str]:
        return list(self._collect_file_hashes(directory_path).keys())

    def _collect_file_hashes(self, directory_path: str) -> Dict[str, str]:
        file_hashes: Dict[str, str] = {}

        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {"node_modules", "dist"}]

            for file_name in files:
                if file_name.startswith("."):
                    continue
                if not file_name.endswith((".md", ".py", ".json", ".ts", ".js")):
                    continue

                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, directory_path).replace("\\", "/")
                with open(full_path, "rb") as handle:
                    file_hashes[rel_path] = hashlib.sha256(handle.read()).hexdigest()

        return dict(sorted(file_hashes.items()))
