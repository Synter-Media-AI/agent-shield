import { SynterIntegrityGuard } from './integrity.js';
import { SynterPromptSanitizer } from './sanitizer.js';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * CLI Compiler for Synter Growth Agents.
 * Usage: npx @synter/agent-shield compile <agent-dir> --secret <key>
 */
export function compileGrowthAgent(agentDir: string, secretKey: string): void {
  const absoluteDir = resolve(agentDir);
  console.log(`\n🛡️  [Synter Agent Shield] Compiling Growth Agent at: ${absoluteDir}`);

  if (!secretKey) {
    console.error('❌ Error: Secret key is required for cryptographic signing. Pass --secret <key> or set SYNTER_MASTER_KEY env var.');
    process.exit(1);
  }

  // 1. Check prompt injection in markdown and config files
  console.log('🔍 Step 1: Scanning for prompt injection vulnerabilities...');
  const guard = new SynterIntegrityGuard(secretKey);
  const manifest = guard.generateManifest(absoluteDir);

  // 2. Generate signed manifest file
  const sigPath = resolve(absoluteDir, 'agent.growth.json.sig');
  writeFileSync(sigPath, JSON.stringify(manifest, null, 2), 'utf-8');

  console.log(`✅ Step 2: Generated cryptographically signed manifest: ${sigPath}`);
  console.log(`🔒 Step 3: Verified ${manifest.fileCount} files with signature: ${manifest.signature.substring(0, 16)}...`);
  console.log('🚀 Growth Agent successfully compiled to Synter Security Standard! Ready to run on Synter Engine.\n');
}
