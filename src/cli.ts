import { SynterIntegrityGuard } from './integrity.js';
import { SynterPromptSanitizer } from './sanitizer.js';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * CLI Compiler for Synter Growth Agents.
 * Usage: SYNTER_MASTER_KEY=<key> npx @synter/agent-shield compile <agent-dir>
 */
export function compileGrowthAgent(agentDir: string, secretKey: string): void {
  const absoluteDir = resolve(agentDir);
  console.log(`\n🛡️  [Synter Agent Shield] Compiling Growth Agent at: ${absoluteDir}`);

  if (!secretKey) {
    console.error('❌ Error: Secret key is required for cryptographic signing. Pass --secret <key> or set SYNTER_MASTER_KEY env var.');
    process.exit(1);
  }

  // 1. Check prompt injection in text-based agent and config files
  console.log('🔍 Step 1: Scanning for prompt injection vulnerabilities...');
  const guard = new SynterIntegrityGuard(secretKey);
  const suspiciousFindings = guard
    .listProtectedFiles(absoluteDir)
    .flatMap((relativePath) => {
      const fullPath = resolve(absoluteDir, relativePath);
      const content = readFileSync(fullPath, 'utf-8');
      const result = SynterPromptSanitizer.inspectExternalText(content);
      return result.findings.map((finding) => ({
        file: relativePath,
        rule: finding.rule,
        match: finding.match
      }));
    });

  if (suspiciousFindings.length > 0) {
    console.error('❌ Compile blocked: suspicious prompt-injection-like content found in agent files.');
    for (const finding of suspiciousFindings) {
      console.error(`   - ${finding.file} [${finding.rule}]: ${finding.match}`);
    }
    process.exit(1);
  }

  const manifest = guard.generateManifest(absoluteDir);

  // 2. Generate signed manifest file
  const sigPath = resolve(absoluteDir, 'agent.growth.json.sig');
  writeFileSync(sigPath, JSON.stringify(manifest, null, 2), 'utf-8');

  console.log(`✅ Step 2: Generated cryptographically signed manifest: ${sigPath}`);
  console.log(`🔒 Step 3: Verified ${manifest.fileCount} files with signature: ${manifest.signature.substring(0, 16)}...`);
  console.log('🚀 Growth Agent successfully compiled to the Agent Shield manifest format.\n');
}
