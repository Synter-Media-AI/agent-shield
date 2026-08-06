import hashlib
import hmac
import os
import re
from typing import Dict, List, Tuple

from ._canonical import canonical_json, secret_bytes

DOMAIN = b"agent-shield/manifest/v1\0"


class SynterIntegrityGuard:
    """
    Generates and verifies signed manifests for agent skill directories.
    """

    def __init__(self, secret_key: str):
        self.secret_key = secret_bytes(secret_key)

    def generate_manifest(self, directory_path: str) -> Dict[str, object]:
        file_hashes = self._collect_file_hashes(self._normalize_root(directory_path))
        unsigned = self._unsigned(file_hashes)
        signature = hmac.new(
            self.secret_key,
            DOMAIN + canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()

        return {
            **unsigned,
            "signature": signature,
        }

    def verify_integrity(self, directory_path: str, manifest: Dict[str, object]) -> Tuple[bool, List[str]]:
        try:
            normalized_root = self._normalize_root(directory_path)
        except (TypeError, ValueError):
            return False, ["INVALID_ROOT: Protected root is invalid."]
        root_violation = self._validate_root(normalized_root)
        if root_violation:
            return False, [root_violation]
        violation = self._validate_manifest(manifest)
        if violation:
            return False, [violation]
        file_hashes = manifest["file_hashes"]
        signature = manifest.get("signature", "")
        expected_signature = hmac.new(
            self.secret_key,
            DOMAIN + canonical_json(self._unsigned(file_hashes)),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, signature):
            return False, ["MANIFEST_SIGNATURE_INVALID: Manifest has been modified or forged!"]

        try:
            current_file_hashes = self._collect_file_hashes(normalized_root)
        except ValueError:
            return False, ["SYMLINK_NOT_ALLOWED: Protected directories may not contain symlinks."]
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
        return list(self._collect_file_hashes(self._normalize_root(directory_path)).keys())

    def _collect_file_hashes(self, directory_path: str) -> Dict[str, str]:
        root_violation = self._validate_root(directory_path)
        if root_violation:
            raise ValueError(root_violation)
        file_hashes: Dict[str, str] = {}

        for root, dirs, files in os.walk(directory_path, onerror=self._raise_walk_error):
            for name in dirs + files:
                if "\\" in name:
                    raise ValueError("Literal backslashes are not portable path names")
                if os.path.islink(os.path.join(root, name)):
                    raise ValueError("Symlinks are not allowed")
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {"node_modules", "dist"}]

            for file_name in files:
                if file_name.startswith("."):
                    continue
                if not file_name.endswith((".md", ".py", ".json", ".ts", ".js")):
                    continue

                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, directory_path).replace("\\", "/")
                if rel_path in file_hashes:
                    raise ValueError(f"Duplicate normalized path: {rel_path}")
                with open(full_path, "rb") as handle:
                    file_hashes[rel_path] = hashlib.sha256(handle.read()).hexdigest()

        return dict(sorted(file_hashes.items()))

    @staticmethod
    def _raise_walk_error(error: OSError) -> None:
        raise ValueError(f"Protected directory could not be inspected: {error}") from error

    @staticmethod
    def _unsigned(file_hashes: Dict[str, str]) -> Dict[str, object]:
        return {"schema_version": "1.0", "algorithm": "hmac-sha256",
                "file_count": len(file_hashes), "file_hashes": file_hashes}

    @staticmethod
    def _validate_manifest(manifest: object):
        if not isinstance(manifest, dict) or manifest.get("schema_version") != "1.0" or manifest.get("algorithm") != "hmac-sha256":
            return "INVALID_MANIFEST: Manifest schema or algorithm is invalid."
        if set(manifest) != {"schema_version", "algorithm", "file_count", "file_hashes", "signature"}:
            return "INVALID_MANIFEST: Manifest contains missing or unsupported fields."
        hashes = manifest.get("file_hashes")
        signature = manifest.get("signature")
        if (not isinstance(hashes, dict) or isinstance(manifest.get("file_count"), bool)
                or not isinstance(manifest.get("file_count"), int) or manifest["file_count"] != len(hashes)
                or not isinstance(signature, str) or len(signature) != 64
                or any(c not in "0123456789abcdef" for c in signature)):
            return "INVALID_MANIFEST: Count, hash map, or signature is invalid."
        for path, digest in hashes.items():
            if (not isinstance(path, str) or not SynterIntegrityGuard._portable_path(path)
                    or not isinstance(digest, str) or len(digest) != 64
                    or any(c not in "0123456789abcdef" for c in digest)):
                return "INVALID_MANIFEST: File paths and SHA-256 hashes must be valid."
        return None

    @staticmethod
    def _validate_root(directory_path: str):
        if not os.path.lexists(directory_path):
            return "INVALID_ROOT: Protected root does not exist or cannot be inspected."
        if os.path.islink(directory_path):
            return "INVALID_ROOT: Protected root must not be a symlink."
        if not os.path.isdir(directory_path):
            return "INVALID_ROOT: Protected root must be a directory."
        return None

    @staticmethod
    def _normalize_root(directory_path: str) -> str:
        if ".." in re.split(r"[\\/]", os.fspath(directory_path)):
            raise ValueError("INVALID_ROOT: Protected root must not contain parent-directory aliases.")
        return os.path.normpath(directory_path)

    @staticmethod
    def _portable_path(path: str) -> bool:
        try:
            path.encode("utf-8")
        except UnicodeError:
            return False
        if not path or "\\" in path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
            return False
        return all(segment not in {"", ".", ".."} for segment in path.split("/"))
