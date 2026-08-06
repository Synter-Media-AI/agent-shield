# Security Policy

## Supported Versions

Security fixes are supported for the latest published `1.x` release.

Because this project is still small and evolving, older releases may not receive backported fixes.

## Reporting A Vulnerability

Do not open a public GitHub issue for suspected vulnerabilities.

Email `hello@syntermedia.ai` with:

- a description of the issue;
- the affected version or commit;
- reproduction steps or a proof of concept;
- any proposed mitigation or fix, if available.

We will acknowledge receipt as soon as possible and coordinate a fix and disclosure timeline.

## Scope Notes

When reporting issues, keep the project’s scope in mind:

- HMAC signing here provides authenticity only for parties that share the same secret.
- Manifest verification here proves file-content consistency against a signed manifest, not artifact provenance.
- Prompt sanitization is heuristic and may have false positives or false negatives.
- Execution policy helpers return decisions, but the host runtime remains responsible for enforcement.
- Timestamp checks provide freshness, not replay prevention; hosts must atomically deduplicate accepted signatures.
- Policy and integrity checks are subject to TOCTOU unless the host checks immediately before use.
- Local audit requires one writer per file and cannot reveal tail truncation/deletion, replacement, or compromise of its HMAC key.
- Deliver 32-byte-or-longer keys through environment variables populated by a secret manager or protected files, never CLI arguments or logs.
