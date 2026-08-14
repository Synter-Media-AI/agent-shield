# Security Policy

## Supported Versions

Security fixes are supported for the latest published release.

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
