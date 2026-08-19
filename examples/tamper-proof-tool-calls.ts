/**
 * Quickstart: Tamper-Proof Tool Calls in Under 2 Minutes
 * 
 * Run with:
 *   npx tsx examples/tamper-proof-tool-calls.ts
 */

import { SynterAgentSigner, SynterExecutionGuard } from "../dist/index.js";

const SECRET_KEY = "example-master-secret-key-at-least-32-chars-long";

// 1. Initialize Signer (Client/Agent runtime) and Guard (Host/Backend execution environment)
const signer = new SynterAgentSigner(SECRET_KEY);
const guard = new SynterExecutionGuard(SECRET_KEY, {
  maxSignatureAgeSeconds: 30,
  allowedActions: ["execute_sql_query", "UPDATE_BUDGET", "send_email"],
  maxSingleBudgetIncreasePercent: 20,
});

console.log("=================================================");
console.log("🛡️  Synter Agent Shield - Interactive Proof Demo");
console.log("=================================================\n");

// Scenario A: Legitimate Signed Tool Dispatch
const legitimatePayload = {
  action: "UPDATE_BUDGET",
  campaignId: "camp_88921",
  currentBudget: 100,
  proposedBudget: 115, // +15% increase (within the 20% limit)
};

const envelope = signer.signPayload(
  "autonomous-bidder-v1",
  "org-synter-4328",
  legitimatePayload
);

console.log("1️⃣ [Agent] Dispatched signed envelope:");
console.log(`   Signature: ${envelope.signature.slice(0, 16)}...`);
console.log(`   Timestamp: ${new Date(envelope.timestamp * 1000).toISOString()}`);

const resultA = guard.authorize(envelope, { recentBudgetChanges: [] });
console.log(`   Verification Result: ${resultA.allowed ? "✅ PASSED" : "❌ BLOCKED"}`);
if (resultA.allowed) {
  console.log("   -> Safe to execute tool side-effect.\n");
}

// Scenario B: Tampered Payload Attack (e.g. Man-in-the-middle or hallucinated argument)
console.log("2️⃣ [Attack] Man-in-the-middle modifies budget to $10,000:");
const tamperedEnvelope = {
  ...envelope,
  payload: {
    ...envelope.payload,
    proposedBudget: 10000, // Attacker changes $115 to $10,000
  },
};

const resultB = guard.authorize(tamperedEnvelope, { recentBudgetChanges: [] });
console.log(`   Verification Result: ${resultB.allowed ? "✅ PASSED" : "❌ BLOCKED"}`);
console.log(`   Violations: ${resultB.violations.join(", ")}\n`);

// Scenario C: Disallowed Action (Prompt injection bypass attempt)
console.log("3️⃣ [Attack] LLM tries calling an unauthorized action:");
const rogueEnvelope = signer.signPayload(
  "autonomous-bidder-v1",
  "org-synter-4328",
  { action: "DROP_DATABASE_TABLE", table: "users" }
);

const resultC = guard.authorize(rogueEnvelope, { recentBudgetChanges: [] });
console.log(`   Verification Result: ${resultC.allowed ? "✅ PASSED" : "❌ BLOCKED"}`);
console.log(`   Violations: ${resultC.violations.join(", ")}\n`);
