# Changelog

All notable changes to this project should be documented in this file.

## [1.0.0] - 2026-08-05

### Added

- TypeScript execution policy helper via `SynterExecutionGuard`.
- TypeScript tamper-evident local audit helper via `SynterAuditTrail`.
- Python integrity helper via `SynterIntegrityGuard`.
- Python execution policy helper via `SynterExecutionGuard`.
- Prompt sanitizer inspection/reporting results in both TypeScript and Python.
- Tests covering integrity verification, policy enforcement, sanitizer findings, and audit chaining.
- Release-readiness docs: `SECURITY.md` and `VERSIONING.md`.

### Changed

- Repositioned the project docs around its real scope as an embeddable security toolkit.
- Updated the CLI compile flow to inspect protected files before manifest generation.
- Tightened examples so they distinguish Agent Shield from the surrounding growth runtime.
- Finalized one cross-language JCS, domain-separated, snake_case envelope and manifest contract with shared golden vectors.
- Made configured budget mutations, manifests, symlink handling, malformed external input, and keyed local audit fail closed.
- Corrected npm/PyPI dependencies, exports, public npm access, packaging smoke checks, and minimum-runtime CI.
