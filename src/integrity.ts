import { createHash, createHmac } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

export interface SkillManifest {
  version: string;
  fileCount: number;
  fileHashes: Record<string, string>;
  signature: string;
}

export class SynterIntegrityGuard {
  private readonly secretKey: Buffer;

  constructor(secretKey: string) {
    this.secretKey = Buffer.from(secretKey, 'utf-8');
  }

  /**
   * Generates a cryptographic manifest of all files in a skills or MCP directory.
   */
  public generateManifest(directoryPath: string): SkillManifest {
    const sortedHashes = this.collectFileHashes(directoryPath);

    const canonicalManifest = JSON.stringify(sortedHashes);
    const signature = createHmac('sha256', this.secretKey)
      .update(canonicalManifest, 'utf-8')
      .digest('hex');

    return {
      version: '1.0.0',
      fileCount: Object.keys(sortedHashes).length,
      fileHashes: sortedHashes,
      signature
    };
  }

  /**
   * Verifies directory contents against a signed skill manifest.
   */
  public verifyIntegrity(
    directoryPath: string,
    manifest: SkillManifest
  ): { valid: boolean; violations: string[] } {
    const { fileHashes, signature } = manifest;
    const violations: string[] = [];

    // 1. Verify manifest signature
    const canonicalManifest = JSON.stringify(fileHashes);
    const expectedSig = createHmac('sha256', this.secretKey)
      .update(canonicalManifest, 'utf-8')
      .digest('hex');

    if (expectedSig !== signature) {
      return {
        valid: false,
        violations: ['MANIFEST_SIGNATURE_INVALID: Manifest has been modified or forged!']
      };
    }

    const currentFileHashes = this.collectFileHashes(directoryPath);

    // 2. Check each file hash
    for (const [relPath, expectedHash] of Object.entries(fileHashes)) {
      const currentHash = currentFileHashes[relPath];
      if (!currentHash) {
        violations.push(`MISSING_FILE: File '${relPath}' was deleted or moved.`);
        continue;
      }

      if (currentHash !== expectedHash) {
        violations.push(`TAMPERED_FILE: File '${relPath}' has been modified or injected with untrusted code!`);
      }
    }

    for (const relPath of Object.keys(currentFileHashes)) {
      if (!(relPath in fileHashes)) {
        violations.push(`UNEXPECTED_FILE: File '${relPath}' was added after compilation.`);
      }
    }

    return {
      valid: violations.length === 0,
      violations
    };
  }

  /**
   * Lists the files that are protected by the integrity manifest.
   */
  public listProtectedFiles(directoryPath: string): string[] {
    return Object.keys(this.collectFileHashes(directoryPath));
  }

  private collectFileHashes(directoryPath: string): Record<string, string> {
    const fileHashes: Record<string, string> = {};

    const walk = (dir: string) => {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        if (entry.startsWith('.') || entry === 'node_modules' || entry === 'dist') continue;
        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);

        if (stat.isDirectory()) {
          walk(fullPath);
        } else if (stat.isFile() && /\.(md|py|json|ts|js)$/.test(entry)) {
          const relPath = relative(directoryPath, fullPath).replace(/\\/g, '/');
          const content = readFileSync(fullPath);
          fileHashes[relPath] = createHash('sha256').update(content).digest('hex');
        }
      }
    };

    walk(directoryPath);

    return Object.keys(fileHashes)
      .sort()
      .reduce((acc, key) => {
        acc[key] = fileHashes[key];
        return acc;
      }, {} as Record<string, string>);
  }
}
