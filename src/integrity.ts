import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, normalize, relative } from 'node:path';
import { canonicalJson, validateUnicodeString, validSecret } from './canonical.js';

export interface SkillManifest {
  schema_version: '1.0';
  algorithm: 'hmac-sha256';
  file_count: number;
  file_hashes: Record<string, string>;
  signature: string;
}

export class SynterIntegrityGuard {
  private readonly secretKey: Buffer;

  constructor(secretKey: string) {
    this.secretKey = validSecret(secretKey);
  }

  /**
   * Generates a cryptographic manifest of all files in a skills or MCP directory.
   */
  public generateManifest(directoryPath: string): SkillManifest {
    const sortedHashes = this.collectFileHashes(this.normalizeRoot(directoryPath));

    const unsigned = this.unsigned(sortedHashes);
    const signature = createHmac('sha256', this.secretKey)
      .update(Buffer.concat([Buffer.from('agent-shield/manifest/v1\0'), Buffer.from(canonicalJson(unsigned))]))
      .digest('hex');

    return {
      ...unsigned,
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
    let normalizedRoot: string;
    try {
      normalizedRoot = this.normalizeRoot(directoryPath);
    } catch (error) {
      return {
        valid: false,
        violations: [error instanceof Error ? error.message : 'INVALID_ROOT: Protected root is invalid.']
      };
    }
    const rootViolation = this.validateRoot(normalizedRoot);
    if (rootViolation) return { valid: false, violations: [rootViolation] };

    const violations = this.validateManifest(manifest);
    if (violations.length) return { valid: false, violations };
    const { file_hashes, signature } = manifest;

    // 1. Verify manifest signature
    const expectedSig = createHmac('sha256', this.secretKey)
      .update(Buffer.concat([Buffer.from('agent-shield/manifest/v1\0'), Buffer.from(canonicalJson(this.unsigned(file_hashes)))]))
      .digest('hex');

    const expected = Buffer.from(expectedSig, 'hex');
    const provided = Buffer.from(signature, 'hex');
    if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
      return {
        valid: false,
        violations: ['MANIFEST_SIGNATURE_INVALID: Manifest has been modified or forged!']
      };
    }

    let currentFileHashes: Record<string, string>;
    try {
      currentFileHashes = this.collectFileHashes(normalizedRoot);
    } catch {
      return {
        valid: false,
        violations: ['SYMLINK_NOT_ALLOWED: Protected directories may not contain symlinks.']
      };
    }

    // 2. Check each file hash
    for (const [relPath, expectedHash] of Object.entries(file_hashes)) {
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
      if (!(relPath in file_hashes)) {
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
    return Object.keys(this.collectFileHashes(this.normalizeRoot(directoryPath)));
  }

  private collectFileHashes(directoryPath: string): Record<string, string> {
    const rootViolation = this.validateRoot(directoryPath);
    if (rootViolation) throw new Error(rootViolation);

    const fileHashes: Record<string, string> = {};

    const walk = (dir: string) => {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        if (entry.includes('\\')) throw new Error('Literal backslashes are not portable path names.');
        const fullPath = join(dir, entry);
        const stat = lstatSync(fullPath);
        if (stat.isSymbolicLink()) throw new Error('Symlinks are not allowed.');
        if (entry.startsWith('.') || entry === 'node_modules' || entry === 'dist') continue;

        if (stat.isDirectory()) {
          walk(fullPath);
        } else if (stat.isFile() && /\.(md|py|json|ts|js)$/.test(entry)) {
          const relPath = relative(directoryPath, fullPath).replace(/\\/g, '/');
          if (relPath in fileHashes) throw new Error(`Duplicate normalized path: ${relPath}`);
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

  private unsigned(file_hashes: Record<string, string>) {
    return {
      schema_version: '1.0' as const,
      algorithm: 'hmac-sha256' as const,
      file_count: Object.keys(file_hashes).length,
      file_hashes
    };
  }

  private validateManifest(value: unknown): string[] {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return ['INVALID_MANIFEST: Manifest must be an object.'];
    const m = value as Partial<SkillManifest>;
    const expectedKeys = ['algorithm', 'file_count', 'file_hashes', 'schema_version', 'signature'];
    if (Object.keys(value).sort().join('\0') !== expectedKeys.join('\0')) {
      return ['INVALID_MANIFEST: Manifest contains missing or unsupported fields.'];
    }
    if (m.schema_version !== '1.0' || m.algorithm !== 'hmac-sha256' || !Number.isSafeInteger(m.file_count) ||
      !m.file_hashes || typeof m.file_hashes !== 'object' || Array.isArray(m.file_hashes) ||
      m.file_count !== Object.keys(m.file_hashes).length || typeof m.signature !== 'string' || !/^[a-f0-9]{64}$/.test(m.signature)) {
      return ['INVALID_MANIFEST: Schema, algorithm, count, hash map, or signature is invalid.'];
    }
    for (const [path, hash] of Object.entries(m.file_hashes)) {
      if (!this.isPortableManifestPath(path) || !/^[a-f0-9]{64}$/.test(hash)) {
        return ['INVALID_MANIFEST: File paths and SHA-256 hashes must be valid.'];
      }
    }
    return [];
  }

  private validateRoot(directoryPath: string): string | undefined {
    try {
      const stat = lstatSync(directoryPath);
      if (stat.isSymbolicLink()) {
        return 'INVALID_ROOT: Protected root must not be a symlink.';
      }
      if (!stat.isDirectory()) {
        return 'INVALID_ROOT: Protected root must be a directory.';
      }
      return undefined;
    } catch {
      return 'INVALID_ROOT: Protected root does not exist or cannot be inspected.';
    }
  }

  private normalizeRoot(directoryPath: string): string {
    if (directoryPath.split(/[\\/]/).includes('..')) {
      throw new Error('INVALID_ROOT: Protected root must not contain parent-directory aliases.');
    }
    return normalize(directoryPath);
  }

  private isPortableManifestPath(path: string): boolean {
    try {
      validateUnicodeString(path, 'Manifest path');
    } catch {
      return false;
    }
    if (!path || path.includes('\\') || path.startsWith('/') || /^[A-Za-z]:/.test(path)) return false;
    return path.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
  }
}
