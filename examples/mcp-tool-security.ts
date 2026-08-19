/**
 * Model Context Protocol (MCP) Tool Execution Security Wrapper
 * 
 * Shows how to guard any MCP server tool call using Agent Shield.
 * 
 * Run with:
 *   npx tsx examples/mcp-tool-security.ts
 */

import { SynterAgentSigner, SynterExecutionGuard } from "../dist/index.js";

const SECRET_KEY = "example-master-secret-key-at-least-32-chars-long";

const signer = new SynterAgentSigner(SECRET_KEY);
const guard = new SynterExecutionGuard(SECRET_KEY, {
  allowedActions: ["pull_ad_metrics", "update_campaign_status"],
});

// Mock MCP Client invoking a tool
function dispatchMcpTool(toolName: string, args: Record<string, unknown>) {
  const envelope = signer.signPayload("mcp-client-agent", "org-marketing-team", {
    action: toolName,
    ...args,
  });

  return envelope;
}

// Mock MCP Server Tool Handler with Agent Shield Gating
function handleMcpToolExecution(signedEnvelope: any) {
  const decision = guard.authorize(signedEnvelope);

  if (!decision.allowed) {
    throw new Error(`[MCP Security Guard] Execution rejected: ${decision.violations.join(", ")}`);
  }

  console.log(`[MCP Tool Router] Executing verified action: ${signedEnvelope.payload.action}`);
  return { status: "success", executedAt: new Date().toISOString() };
}

// 1. Authorized Tool Call
console.log("▶️ Dispatching authorized MCP tool call (pull_ad_metrics)...");
const validCall = dispatchMcpTool("pull_ad_metrics", { platform: "google_ads", dateRange: "last_7d" });
const result1 = handleMcpToolExecution(validCall);
console.log("   Result:", result1);

// 2. Unauthorized Tool Call Attempt
console.log("\n▶️ Dispatching unauthorized MCP tool call (drop_database)...");
const unauthorizedCall = dispatchMcpTool("drop_database", {});
try {
  handleMcpToolExecution(unauthorizedCall);
} catch (err: any) {
  console.log("   Blocked by Shield:", err.message);
}
