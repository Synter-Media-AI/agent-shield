#!/usr/bin/env node

import { compileGrowthAgent } from '../dist/cli.js';

const args = process.argv.slice(2);
const command = args[0];

if (command === 'compile') {
  const dir = args[1] || '.';
  const secretIdx = args.indexOf('--secret');
  const secret = secretIdx !== -1 ? args[secretIdx + 1] : process.env.SYNTER_MASTER_KEY;

  compileGrowthAgent(dir, secret);
} else {
  console.log(`
🛡️  Synter Agent Shield CLI (v1.0.0)
Commands:
  npx @synter/agent-shield compile <dir> --secret <key>   Scan protected files and emit a signed manifest
  `);
}
