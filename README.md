# Agent Shield

Agent Shield is a small, embeddable security toolkit for agent hosts. It provides interoperable TypeScript and Python helpers for:

- HMAC-authenticated execution envelopes;
- signed directory-integrity manifests;
- fail-closed action and budget policy checks;
- heuristic prompt-injection scanning; and
- a keyed, hash-linked local TypeScript audit trail.

It does not run agents or call ad platforms. Your host remains responsible for key custody, replay deduplication, authorization enforcement, filesystem isolation, and durable audit storage.

## Install

```bash
npm install @synter/agent-shield
pip install synter-agent-shield
```

Use a secret string containing at least 32 UTF-8 bytes. Load it from a secret manager or protected file; never put it in source, command-line arguments, or logs.

## TypeScript quickstart

```ts
import {
  SynterAgentSigner,
  SynterExecutionGuard,
  type SignedPayloadEnvelope
} from '@synter/agent-shield';

const secret = process.env.SYNTER_MASTER_KEY;
if (!secret) throw new Error('SYNTER_MASTER_KEY is required');

const signer = new SynterAgentSigner(secret);
const envelope: SignedPayloadEnvelope = signer.signPayload('budget-agent', 'org-123', {
  action: 'SET_BUDGET',
  campaign_id: 'campaign-456',
  current_budget: 100,
  proposed_budget: 120
});

const verification = signer.verifySignature(envelope);
if (!verification.valid) {
  throw new Error(verification.error);
}

const guard = new SynterExecutionGuard(secret, {
  allowedActions: ['SET_BUDGET'],
  maxSingleBudgetIncreasePercent: 25,
  maxCumulativeBudgetIncreasePercent24h: 30
});
const decision = guard.authorize(envelope, { recentBudgetChanges: [] });
if (!decision.allowed) {
  console.error(decision.violations);
  process.exitCode = 1;
} else {
  // Execute only after this final check, and atomically record the signature
  // as consumed for the full acceptance window.
  console.log('authorized increase', decision.budgetIncreasePercent);
}
```

## Python quickstart

```python
import os

from synter_shield import SynterAgentSigner, SynterExecutionGuard

secret = os.environ.get("SYNTER_MASTER_KEY")
if not secret:
    raise RuntimeError("SYNTER_MASTER_KEY is required")

signer = SynterAgentSigner(secret)
envelope = signer.sign_payload(
    "budget-agent",
    "org-123",
    {
        "action": "SET_BUDGET",
        "campaign_id": "campaign-456",
        "current_budget": 100,
        "proposed_budget": 120,
    },
)

valid, error = signer.verify_signature(envelope)
if not valid:
    raise RuntimeError(error)

guard = SynterExecutionGuard(
    secret,
    {
        "allowed_actions": ["SET_BUDGET"],
        "max_single_budget_increase_percent": 25,
        "max_cumulative_budget_increase_percent_24h": 30,
    },
)
allowed, violations, increase = guard.authorize(envelope, [])
if not allowed:
    raise RuntimeError("; ".join(violations))
print("authorized increase", increase)
```

## CLI: scan and compile a manifest

The packaged CLI reads `SYNTER_MASTER_KEY_FILE` (preferred) or `SYNTER_MASTER_KEY`. A key file may end with a newline; trailing CR/LF characters are removed.

```bash
install -m 600 /dev/null /run/secrets/agent-shield
printf '%s' 'replace-with-at-least-32-secret-bytes' > /run/secrets/agent-shield
SYNTER_MASTER_KEY_FILE=/run/secrets/agent-shield \
  npx @synter/agent-shield compile ./agent
```

The command scans protected text, rejects suspicious findings, and writes `agent.growth.json.sig`. The output manifest itself is excluded only if its extension or location is excluded; compile into a reviewed fixture and verify before loading it.

## Signer

`SynterAgentSigner` authenticates an exact JSON payload and identity pair. Verification returns a result rather than throwing on malformed external envelopes.

```ts
const signed = signer.signPayload('agent-1', 'org-1', { action: 'READ' });
const result = signer.verifySignature(signed, 300);
```

```python
signed = signer.sign_payload("agent-1", "org-1", {"action": "READ"})
valid, error = signer.verify_signature(signed, max_age_seconds=300)
```

Timestamp validation provides **freshness, not replay prevention**. A host must atomically deduplicate an accepted envelope or signature for the entire acceptance window. Verification permits at most 30 seconds of future clock skew.

## Execution policy

The default budget mutation actions are `SET_BUDGET`, `UNCAP_BUDGET`, and `UPDATE_BUDGET`. They require a nonempty `campaign_id`, a finite `current_budget > 0`, and a finite `proposed_budget >= 0`. Default single-action and cumulative-per-campaign 24-hour caps are both 30%.

```ts
const guard = new SynterExecutionGuard(secret, {
  allowedActions: ['READ', 'SET_BUDGET'],
  budgetMutationActions: ['SET_BUDGET'],
  maxSignatureAgeSeconds: 120,
  maxSingleBudgetIncreasePercent: 10,
  maxCumulativeBudgetIncreasePercent24h: 20
});
```

```python
guard = SynterExecutionGuard(secret, {
    "allowed_actions": ["READ", "SET_BUDGET"],
    "budget_mutation_actions": ["SET_BUDGET"],
    "max_signature_age_seconds": 120,
    "max_single_budget_increase_percent": 10,
    "max_cumulative_budget_increase_percent_24h": 20,
})
```

Policy arrays are snapshotted at construction (and the TypeScript snapshot is frozen). Malformed policy, context, budget data, and history deny rather than default. Hosts must supply complete recent history and enforce the returned decision immediately before execution; a prior check cannot eliminate a time-of-check/time-of-use race.

## Integrity manifests

```ts
import { SynterIntegrityGuard } from '@synter/agent-shield';

const integrity = new SynterIntegrityGuard(secret);
const manifest = integrity.generateManifest('./agent');
const result = integrity.verifyIntegrity('./agent', manifest);
if (!result.valid) throw new Error(result.violations.join('\n'));
```

```python
from synter_shield import SynterIntegrityGuard

integrity = SynterIntegrityGuard(secret)
manifest = integrity.generate_manifest("./agent")
valid, violations = integrity.verify_integrity("./agent", manifest)
if not valid:
    raise RuntimeError("\n".join(violations))
```

The root must exist, be a real directory, and not be a symlink. Child symlinks and literal backslashes in POSIX names are rejected. Protected extensions are `.md`, `.py`, `.json`, `.ts`, and `.js`; hidden entries, `node_modules`, and `dist` are skipped. Manifest paths are portable relative POSIX paths with no empty, `.` or `..` segments, drive prefix, absolute prefix, or backslash.

Manifest verification catches wrong signatures, missing files, changed files, and unexpected protected files. It does not lock the tree: verify immediately before use or load from an immutable snapshot to reduce TOCTOU exposure.

## Prompt sanitizer

```ts
import { SynterPromptSanitizer } from '@synter/agent-shield';

const inspected = SynterPromptSanitizer.inspectExternalText(scrapedText);
console.log(inspected.findings);
sendToModel(inspected.sanitized);
```

```python
from synter_shield import SynterPromptSanitizer

inspected = SynterPromptSanitizer.inspect_external_text(scraped_text)
print(inspected["findings"])
send_to_model(inspected["sanitized"])
```

The scanner is heuristic. It can produce false positives and false negatives and does not certify text as safe.

## TypeScript audit trail

```ts
import { SynterAuditTrail } from '@synter/agent-shield';

const audit = new SynterAuditTrail(secret);
audit.appendEntry('./var/audit.jsonl', {
  agent_id: 'budget-agent',
  organization_id: 'org-123',
  action: 'SET_BUDGET',
  decision: 'allowed',
  payload: { campaign_id: 'campaign-456', proposed_budget: 120 }
});
const check = audit.verify('./var/audit.jsonl');
if (!check.valid) throw new Error(check.violations.join('\n'));
```

Use exactly one writer per audit file; there is no cross-process lock. The keyed chain detects edits and reordering while the key remains secret. It cannot detect tail truncation, whole-file deletion/replacement, or compromise of the HMAC key. Export logs to durable append-only storage when those threats matter.

## Exact v1 wire contract

Both implementations use RFC 8785 JSON Canonicalization Scheme (JCS), lowercase 64-character hex HMAC-SHA-256, UTF-8, and domain separation. `\0` below means one **NUL byte, byte `0x00`**, not two backslash/zero characters.

Envelope signed bytes:

```text
UTF-8("agent-shield/envelope/v1") || 0x00 || JCS(unsigned_envelope)
```

The unsigned envelope has exactly these fields:

```json
{
  "schema_version": "1.0",
  "algorithm": "hmac-sha256",
  "agent_id": "nonempty string",
  "organization_id": "nonempty string",
  "timestamp": 1700000000,
  "payload": {}
}
```

The transmitted envelope adds exactly `signature`; extra top-level fields are rejected.

Manifest signed bytes:

```text
UTF-8("agent-shield/manifest/v1") || 0x00 || JCS(unsigned_manifest)
```

The unsigned manifest has exactly `schema_version`, `algorithm`, `file_count`, and `file_hashes`. The transmitted manifest adds exactly `signature`; extra top-level fields are rejected. Future extensions require a new schema rather than optional v1 fields.

JSON values are limited to null, booleans, valid Unicode strings, arrays, plain/string-keyed objects, and finite numbers. Lone UTF-16 surrogates are rejected in every string, key, identifier, and secret. Integer-valued numbers must be within `±(2^53−1)`. Timestamps are positive safe integers in Unix seconds. Shared vectors, including numeric boundaries, live in [`vectors/golden-v1.json`](vectors/golden-v1.json).

## Architecture

```text
producer/runtime
  └─ SynterAgentSigner ── exact signed envelope ──▶ host boundary
                                                       ├─ verify freshness/signature
reviewed agent directory ─▶ signed manifest ──────────┤  verify immutable files
external text ─────────────▶ prompt sanitizer ────────┤  inspect/redact
budget history + policy ───▶ execution guard ─────────┤  allow/deny
                                                       └─ execute + dedupe + durable audit
```

The shared secret authenticates parties that possess it; it does not identify which holder signed an item. Separate trust domains should use separate keys.

## Scope, guarantees, and non-goals

Agent Shield guarantees deterministic cross-language signing for supported v1 JSON, constant-time digest comparison after structural validation, exact top-level schemas, fail-closed policy checks, and content comparison against a valid signed manifest.

Agent Shield does **not** provide asymmetric identity, key storage/rotation, network transport security, process sandboxing, agent scheduling, platform API clients, atomic replay storage, filesystem locking, an immutable artifact store, or complete prompt-injection prevention. It cannot remove host-level TOCTOU. Local audit is not a transparency log and assumes a single writer.

See [SECURITY.md](SECURITY.md), [VERSIONING.md](VERSIONING.md), [CHANGELOG.md](CHANGELOG.md), and [EXAMPLES.md](EXAMPLES.md).

## Development

```bash
npm ci
npm test
python -m pip install .
python -m unittest discover -s synter_shield/tests -v
```

Release CI additionally installs the real npm tarball and Python wheel into clean consumers and exercises imports, signing, verification, and the packaged CLI.
