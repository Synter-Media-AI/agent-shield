# Versioning And Stability

Agent Shield follows semantic versioning for its documented public APIs.

## Stable Surface

The following are considered the stable public surface in `2.x`:

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
- TypeScript and Python intent signatures share the `synter.intent.v2` wire protocol and golden test vectors. Their public envelope field names remain idiomatic to each language.
- Manifest and audit JSON field names are language-specific and are not interchangeable between TypeScript and Python.

## Migrating From 1.x

Version 2 intentionally does not treat version 1 artifacts as authenticated version 2 data:

1. deploy version 2 verifiers before accepting new version 2 intents;
2. regenerate every skill manifest with version 2;
3. archive version 1 audit logs read-only and begin a new version 2 ledger;
4. persist each version 2 audit checkpoint in durable storage outside the local ledger if truncation detection is required.
