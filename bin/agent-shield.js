#!/usr/bin/env node

import { compileGrowthAgent } from '../dist/cli.js';
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const command = args[0];

if (command === 'compile') {
  const dir = args[1] || '.';
  const secret = process.env.SYNTER_MASTER_KEY_FILE
    ? readFileSync(process.env.SYNTER_MASTER_KEY_FILE, 'utf8').replace(/[\r\n]+$/, '')
    : process.env.SYNTER_MASTER_KEY;

  compileGrowthAgent(dir, secret ?? '');
} else {
  console.log(`
🛡️  Synter Agent Shield CLI (v1.0.0)
Commands:
  SYNTER_MASTER_KEY_FILE=/secure/key agent-shield compile <dir>
  `);
}
