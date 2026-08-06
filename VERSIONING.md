# Versioning And Stability

Agent Shield follows semantic versioning for its documented public APIs.

## Stable Surface

The following are considered the stable public surface in `1.x`:

- exported TypeScript symbols from `src/index.ts`;
- exported Python symbols from `synter_shield.__init__`;
- the manifest field names emitted by `SynterIntegrityGuard`;
- the signed envelope structure emitted by `SynterAgentSigner`;
- the decision/result shapes returned by the sanitizer, integrity, and policy helpers.

## What May Change In A Minor Release

The following may change in minor releases if they do not break the documented surface:

- additional sanitizer detection rules;
- new optional fields in result objects;
- new helper exports;
- clearer violation messages.

## Breaking Changes

The following require a major version bump:

- changing existing manifest field names or envelope field names;
- removing or renaming exported public classes or functions;
- changing default behavior in a way that breaks documented examples or host integrations.

## Compatibility Guidance

- Pin exact versions if your runtime depends on specific sanitizer findings or violation text.
- Prefer consuming structured fields over parsing human-readable error strings.
- Envelope and manifest `schema_version` are `"1.0"` and are independent of package version `1.0.0`.
- Wire fields, JCS/domain bytes, signature encoding, 30-second future skew, JSON limits, and default budget-action semantics are compatibility-sensitive and require a major release to change incompatibly.
