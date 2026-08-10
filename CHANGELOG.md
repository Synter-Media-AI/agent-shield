# Changelog

All notable changes to this project should be documented in this file.

## [2.0.0] - 2026-08-10

### Added

- Added the Python authenticated local audit helper via `SynterAuditTrail`.

### Security

- Replaced delimiter-concatenated intent signatures with the domain-separated `synter.intent.v2` structured protocol, including safe typed canonicalization, strict envelopes, and shared TypeScript/Python test vectors.
- Made malformed budget actions and missing or malformed 24-hour budget history fail closed; empty action allowlists now deny every action.
- Upgraded manifests to schema `2.0.0`, signed all recognized metadata, rejected unknown fields and unsafe roots, and protected every regular file except the generated root manifest.
- Upgraded audit records to schema `2.0.0`, authenticated an existing chain before append, rejected malformed or empty ledgers, and added external checkpoints for detecting truncation and valid-prefix rollback.
- Added CodeQL, Dependabot, package-install smoke tests, and supported-Python compatibility checks.

### Breaking

- Version 1 intent signatures, manifests, and audit records are not accepted as version 2 authenticated artifacts. Re-sign intents, regenerate manifests, and start a new audit ledger at the migration boundary.
- `SynterAuditTrail` requires a secret key and assumes one writer per ledger.

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
