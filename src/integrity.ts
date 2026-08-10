import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readFileSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';

export interface SkillManifest {
  algorithm: 'hmac-sha256';
  version: string;
  fileCount: number;
  fileHashes: Record<string, string>;
  signature: string;
}

export class SynterIntegrityGuard {
  private static readonly MANIFEST_VERSION = '2.0.0';
  private static readonly SIGNATURE_HEX_LENGTH = 64;
  private readonly secretKey: Buffer;

  constructor(secretKey: string) {
    if (!secretKey || secretKey.trim().length === 0) {
      throw new Error('SynterIntegrityGuard requires a non-empty secret key.');
    }
    this.secretKey = Buffer.from(secretKey, 'utf-8');
  }

  /**
   * Generates a cryptographic manifest of all files in a skills or MCP directory.
   */
  public generateManifest(directoryPath: string): SkillManifest {
    const sortedHashes = this.collectFileHashes(directoryPath);

    const signedData = this.buildSignedManifestData(sortedHashes);
    const canonicalManifest = JSON.stringify(signedData);
    const signature = createHmac('sha256', this.secretKey)
      .update(canonicalManifest, 'utf-8')
      .digest('hex');

    return {
      ...signedData,
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
    const manifestValidation = this.validateManifest(manifest);
    if (manifestValidation.length > 0) {
      return { valid: false, violations: manifestValidation };
    }

    const { fileHashes, signature } = manifest;
    const violations: string[] = [];

    // 1. Verify manifest signature
    const canonicalManifest = JSON.stringify(this.buildSignedManifestData(fileHashes));
    const expectedSig = createHmac('sha256', this.secretKey)
      .update(canonicalManifest, 'utf-8')
      .digest('hex');

    if (!this.signaturesMatch(expectedSig, signature)) {
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
      if (!Object.prototype.hasOwnProperty.call(fileHashes, relPath)) {
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
    const rootStat = lstatSync(directoryPath);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
      throw new Error(`SynterIntegrityGuard requires a real, non-symlink directory: ${directoryPath}`);
    }

    const fileHashes: Record<string, string> = Object.create(null) as Record<string, string>;

    const walk = (dir: string) => {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const stat = lstatSync(fullPath);

        if (stat.isSymbolicLink()) {
          throw new Error(`SynterIntegrityGuard does not allow symlinks inside protected directories: ${fullPath}`);
        }

        if (stat.isDirectory()) {
          walk(fullPath);
        } else if (stat.isFile()) {
          const relPath = relative(directoryPath, fullPath).replace(/\\/g, '/');
          if (relPath === 'agent.growth.json.sig') continue;
          const descriptor = openSync(fullPath, constants.O_RDONLY | constants.O_NOFOLLOW);
          let content: Buffer;
          try {
            if (!fstatSync(descriptor).isFile()) {
              throw new Error(`SynterIntegrityGuard only protects regular files: ${fullPath}`);
            }
            content = readFileSync(descriptor);
          } finally {
            closeSync(descriptor);
          }
          fileHashes[relPath] = createHash('sha256').update(content).digest('hex');
        } else {
          throw new Error(`SynterIntegrityGuard only allows regular files and directories: ${fullPath}`);
        }
      }
    };

    walk(directoryPath);

    return Object.keys(fileHashes)
      .sort()
      .reduce((acc, key) => {
        acc[key] = fileHashes[key];
        return acc;
      }, Object.create(null) as Record<string, string>);
  }

  private buildSignedManifestData(fileHashes: Record<string, string>): Omit<SkillManifest, 'signature'> {
    return {
      algorithm: 'hmac-sha256',
      version: SynterIntegrityGuard.MANIFEST_VERSION,
      fileCount: Object.keys(fileHashes).length,
      fileHashes
    };
  }

  private signaturesMatch(expectedSignature: string, providedSignature: string): boolean {
    const expected = Buffer.from(expectedSignature, 'utf-8');
    const provided = Buffer.from(providedSignature, 'utf-8');
    return expected.length === provided.length && timingSafeEqual(expected, provided);
  }

  private validateManifest(manifest: SkillManifest): string[] {
    const violations: string[] = [];
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
      return ['INVALID_MANIFEST: Manifest must be an object.'];
    }

    const expectedKeys = ['algorithm', 'fileCount', 'fileHashes', 'signature', 'version'];
    const actualKeys = Object.keys(manifest).sort();
    if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
      violations.push('INVALID_MANIFEST: Manifest contains missing or unsupported top-level fields.');
    }

    const entries = manifest.fileHashes;

    if (manifest?.algorithm !== 'hmac-sha256') {
      violations.push('UNSUPPORTED_MANIFEST_ALGORITHM: Only hmac-sha256 manifests are supported.');
    }

    if (manifest?.version !== SynterIntegrityGuard.MANIFEST_VERSION) {
      violations.push(`UNSUPPORTED_MANIFEST_VERSION: Expected ${SynterIntegrityGuard.MANIFEST_VERSION}.`);
    }

    if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
      violations.push('INVALID_MANIFEST: fileHashes must be an object map of relative paths to sha256 digests.');
      return violations;
    }

    if (!Number.isInteger(manifest.fileCount) || manifest.fileCount !== Object.keys(entries).length) {
      violations.push('INVALID_MANIFEST: fileCount does not match fileHashes.');
    }

    if (
      typeof manifest.signature !== 'string' ||
      manifest.signature.length !== SynterIntegrityGuard.SIGNATURE_HEX_LENGTH ||
      !/^[a-f0-9]+$/i.test(manifest.signature)
    ) {
      violations.push('INVALID_MANIFEST: signature must be a 64-character hex digest.');
    }

    for (const [path, hash] of Object.entries(entries)) {
      if (
        path.length === 0 ||
        path.includes('\\') ||
        path.includes('\0') ||
        path.split('/').includes('..') ||
        isAbsolute(path) ||
        /^[a-zA-Z]:/.test(path)
      ) {
        violations.push(`INVALID_MANIFEST_PATH: '${path}' is not a safe relative path.`);
      }
      if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash)) {
        violations.push(`INVALID_MANIFEST_HASH: '${path}' does not contain a valid sha256 digest.`);
      }
    }

    return violations;
  }
}
