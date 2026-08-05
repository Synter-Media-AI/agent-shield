# 🎯 Detailed Use Cases for Synter Growth Agents & Agent Shield

This guide details real-world use cases where growth teams, agencies, and performance marketers build custom Growth Agents using **Claude**, **OpenAI**, or **Synter Campaign IDE**, compile them using **Agent Shield**, and execute them safely.

---

## 🚀 Use Case 1: Uncapped CPA Defense & Auction Loss Bidding Agent

### Problem
High-converting campaigns (e.g. Google PMax or Meta Retargeting) frequently get throttled by artificial daily budget caps or low max CPC bids, causing lost impression share (`Search Lost IS (Budget)` > 25%).

### Solution
An autonomous **CPA Defense Agent** monitors performance every 4 hours:
1. Checks 7-day CPA against the client's Target CPA threshold.
2. If CPA is 15%+ below Target CPA and Search Lost IS (Budget) > 10%, the agent uncaps daily budget by +20% steps.
3. Automatically increases target ROAS / bid modifiers to win top ad auctions.

### Agent Shield Security Enforcement
* **Budget Step Caps**: `@synter/agent-shield` validates that no single action can increase budget by more than +30% per 24 hours.
* **Payload Signing**: Every bid adjustment is signed with `SynterAgentSigner` to prevent replay attacks or unauthorized API mutations.

---

## 💳 Use Case 2: Card-Backed SaaS Trial Acquisition Agent

### Problem
Ad platforms frequently optimize for cheap signup proxies (disposable emails, bot traffic) that never enter a credit card, inflating ad platform ROAS while trial MRR remains flat.

### Solution
A **Card-Backed Trial Growth Agent**:
1. Connects ad platform campaigns with downstream product telemetry (Stripe / PostHog).
2. Ranks ad groups by **Card-Backed Trial Start Rate** instead of raw account signups.
3. Pauses ad sets where card conversion rate < 2.5% and reallocates budget to high-intent search keywords.

### Agent Shield Security Enforcement
* **Integrity Guard**: `SynterIntegrityGuard` verifies the SHA-256 manifest of the skill file (`card_backed_trial_optimizer.md`) to guarantee that prompt instructions cannot be altered or injected with malicious redirect URLs.

---

## 📊 Use Case 3: Cross-Platform Budget Pacing & Capital Reallocation Agent

### Problem
Capital gets trapped in underperforming Meta or LinkedIn ad sets while Google Search or Reddit ad sets are budget-starved and delivering 3x higher ROAS.

### Solution
A **Cross-Platform Pacing Agent**:
1. Pulls 7-day cross-platform metrics across Google, Meta, LinkedIn, Reddit, X, and TikTok.
2. Identifies channels exceeding blended ROAS targets.
3. Decreases budget on underperforming channels by -15% and shifts capital to top-performing platforms in real-time.

### Agent Shield Security Enforcement
* **Prompt Sanitizer**: `SynterPromptSanitizer` cleans scraped landing page copy and external ad creative text to strip prompt injection patterns before feeding data into the LLM context.

---

## ⚡ Use Case 4: Offline Stripe Conversion Upload & Phantom ROAS Elimination

### Problem
Browser-based ad pixels drop 20-30% of conversions due to ad blockers and iOS privacy restrictions, causing ad platforms to bid blindly.

### Solution
An **Offline Conversion Sync Agent**:
1. Listens to Stripe `checkout.session.completed` and `customer.subscription.created` webhooks.
2. Extracts Google `gclid`, Meta `fbp`/`fbc`, and Reddit `rdt_cid` click identifiers.
3. Uploads verified conversion value directly to Google Ads CAPI, Meta CAPI, and Reddit CAPI.

### Agent Shield Security Enforcement
* **Signed Action Audit**: Every conversion upload is cryptographically signed and recorded in an immutable audit trail (`agent_tool_executions`).

---

## 🏢 Use Case 5: Multi-Client Agency Growth Swarm

### Problem
Marketing agencies managing 30+ client workspaces struggle to enforce brand guidelines and spend safety controls across multiple junior media buyers and AI tools.

### Solution
The agency builds client-specific Growth Agents in **Claude** or **OpenAI**, compiles each agent with `npx @synter/agent-shield compile`, and deploys them to Synter's 24/7 background execution engine.

### Workflow
```bash
# Compile Agency Client A Agent
npx @synter/agent-shield compile ./agents/client-a-growth --secret $CLIENT_A_KEY

# Compile Agency Client B Agent
npx @synter/agent-shield compile ./agents/client-b-growth --secret $CLIENT_B_KEY
```
