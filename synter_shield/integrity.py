import hashlib
import hmac
import json
import os
import stat
from typing import Dict, List, Tuple


class SynterIntegrityGuard:
    """
    Generates and verifies signed manifests for agent skill directories.
    """

    MANIFEST_VERSION = "2.0.0"

    def __init__(self, secret_key: str):
        if not isinstance(secret_key, str) or len(secret_key.encode("utf-8")) < 32:
            raise ValueError("SynterIntegrityGuard requires a secret key containing at least 32 UTF-8 bytes.")
        self.secret_key = secret_key.encode("utf-8")

    def generate_manifest(self, directory_path: str) -> Dict[str, object]:
        file_hashes = self._collect_file_hashes(directory_path)
        signed_data = self._build_signed_manifest_data(file_hashes)
        canonical_manifest = json.dumps(signed_data, sort_keys=True)
        signature = hmac.new(
            self.secret_key,
            canonical_manifest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            **signed_data,
            "signature": signature,
        }

    def verify_integrity(self, directory_path: str, manifest: Dict[str, object]) -> Tuple[bool, List[str]]:
        manifest_violations = self._validate_manifest(manifest)
        if manifest_violations:
            return False, manifest_violations

        file_hashes = manifest.get("file_hashes", {})
        signature = manifest.get("signature", "")
        canonical_manifest = json.dumps(self._build_signed_manifest_data(file_hashes), sort_keys=True)
        expected_signature = hmac.new(
            self.secret_key,
            canonical_manifest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, signature):
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
        try:
            root_stat = os.lstat(directory_path)
        except FileNotFoundError as exc:
            raise ValueError(f"SynterIntegrityGuard directory does not exist: {directory_path}") from exc
        if os.path.islink(directory_path) or not os.path.isdir(directory_path):
            raise ValueError(
                f"SynterIntegrityGuard requires a real, non-symlink directory: {directory_path}"
            )

        file_hashes: Dict[str, str] = {}

        for root, dirs, files in os.walk(directory_path):
            for name in dirs + files:
                full_path = os.path.join(root, name)
                if os.path.islink(full_path):
                    raise ValueError(
                        f"SynterIntegrityGuard does not allow symlinks inside protected directories: {full_path}"
                    )

            for file_name in files:
                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, directory_path).replace("\\", "/")
                if rel_path == "agent.growth.json.sig":
                    continue
                file_stat = os.lstat(full_path)
                if not stat.S_ISREG(file_stat.st_mode):
                    raise ValueError(
                        f"SynterIntegrityGuard only protects regular files: {full_path}"
                    )
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(full_path, flags)
                try:
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise ValueError(
                            f"SynterIntegrityGuard only protects regular files: {full_path}"
                        )
                    with os.fdopen(descriptor, "rb", closefd=False) as handle:
                        file_hashes[rel_path] = hashlib.sha256(handle.read()).hexdigest()
                finally:
                    os.close(descriptor)

        return dict(sorted(file_hashes.items()))

    def _build_signed_manifest_data(self, file_hashes: Dict[str, str]) -> Dict[str, object]:
        return {
            "algorithm": "hmac-sha256",
            "version": self.MANIFEST_VERSION,
            "file_count": len(file_hashes),
            "file_hashes": file_hashes,
        }

    def _validate_manifest(self, manifest: Dict[str, object]) -> List[str]:
        if not isinstance(manifest, dict):
            return ["INVALID_MANIFEST: Manifest must be an object."]

        violations: List[str] = []
        file_hashes = manifest.get("file_hashes")

        expected_keys = {"algorithm", "version", "file_count", "file_hashes", "signature"}
        if set(manifest) != expected_keys:
            violations.append(
                "INVALID_MANIFEST: Manifest contains missing or unsupported top-level fields."
            )

        if manifest.get("algorithm") != "hmac-sha256":
            violations.append("UNSUPPORTED_MANIFEST_ALGORITHM: Only hmac-sha256 manifests are supported.")

        if manifest.get("version") != self.MANIFEST_VERSION:
            violations.append(f"UNSUPPORTED_MANIFEST_VERSION: Expected {self.MANIFEST_VERSION}.")

        if not isinstance(file_hashes, dict):
            violations.append(
                "INVALID_MANIFEST: file_hashes must be an object map of relative paths to sha256 digests."
            )
            return violations

        if type(manifest.get("file_count")) is not int or manifest.get("file_count") != len(file_hashes):
            violations.append("INVALID_MANIFEST: file_count does not match file_hashes.")

        signature = manifest.get("signature")
        if (
            not isinstance(signature, str)
            or len(signature) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in signature)
        ):
            violations.append("INVALID_MANIFEST: signature must be a 64-character hex digest.")

        for path, digest in file_hashes.items():
            if (
                not isinstance(path, str)
                or not path
                or "\\" in path
                or "\x00" in path
                or ".." in path.split("/")
                or os.path.isabs(path)
                or (len(path) >= 2 and path[1] == ":")
            ):
                violations.append(f"INVALID_MANIFEST_PATH: '{path}' is not a safe relative path.")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in digest)
            ):
                violations.append(f"INVALID_MANIFEST_HASH: '{path}' does not contain a valid sha256 digest.")

        return violations
