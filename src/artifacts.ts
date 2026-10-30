import { open, realpath, lstat } from 'node:fs/promises';
import path from 'node:path';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { AnalysisError } from './contracts.js';
import type { Limits } from './contracts.js';

export function underRoot(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export function validateLocalPath(candidate: string): void {
  // Refuse UNC/device paths and NTFS alternate streams. Ordinary local drive
  // letters are accepted; format content never supplies paths to follow.
  if (/^[\\/]{2}/.test(candidate) || candidate.includes('\0')) {
    throw new AnalysisError('unsupported_path', 'Only local filesystem paths are admitted');
  }
  if (process.platform === 'win32' && candidate.slice(2).includes(':')) {
    throw new AnalysisError('unsupported_path', 'Alternate streams are not admitted');
  }
}

export async function readSnapshot(input: string, roots: readonly string[], limits: Limits) {
  validateLocalPath(input);
  const lexical = path.resolve(input);
  if (!roots.some(root => underRoot(lexical, root))) throw new AnalysisError('outside_root', 'Outside authorized roots');
  const resolved = await realpath(lexical);
  if (!roots.some(root => underRoot(resolved, root))) throw new AnalysisError('outside_root', 'Resolved outside authorized roots');
  const link = await lstat(resolved, { bigint: true });
  if (!link.isFile() || link.isSymbolicLink()) throw new AnalysisError('not_regular_file', 'Regular file required');
  const handle = await open(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) throw new AnalysisError('not_regular_file', 'Regular file required');
    if (before.ino !== link.ino || before.dev !== link.dev) throw new AnalysisError('artifact_changed', 'Identity changed', 'unknown');
    if (before.size > BigInt(limits.maxInputBytes)) throw new AnalysisError('input_limit', 'Input cap exceeded', 'unknown');
    const bytes = Buffer.alloc(Number(before.size));
    const hash = createHash('sha256');
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, Math.min(64 * 1024, bytes.length - offset), offset);
      if (bytesRead === 0) throw new AnalysisError('artifact_changed', 'Short read', 'unknown');
      hash.update(bytes.subarray(offset, offset + bytesRead));
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const finalPath = await realpath(lexical);
    const finalStat = await lstat(finalPath, { bigint: true });
    if (finalPath !== resolved || before.size !== after.size || before.mtimeNs !== after.mtimeNs ||
        before.ctimeNs !== after.ctimeNs || finalStat.ino !== before.ino || finalStat.dev !== before.dev ||
        finalStat.size !== before.size || finalStat.mtimeNs !== before.mtimeNs || finalStat.isSymbolicLink()) {
      throw new AnalysisError('artifact_changed', 'Snapshot changed', 'unknown');
    }
    return { bytes, artifact: { sha256: hash.digest('hex'), bytes: bytes.length } };
  } finally { await handle.close(); }
}

export function identifyFormat(b: Buffer): { format: string; basis: string } {
  const starts = (magic: number[]) => magic.every((value, i) => b[i] === value);
  if (starts([0, 97, 115, 109])) return { format: 'wasm', basis: 'magic-only; structural validation pending' };
  if (starts([127, 69, 76, 70])) return { format: 'native-elf', basis: 'magic-only; structural validation pending' };
  if (starts([77, 90])) return { format: 'native-pe-candidate', basis: 'DOS magic only; PE validation pending' };
  if (starts([80, 75, 3, 4])) return { format: 'archive-zip', basis: 'magic-only; central directory validation pending' };
  if (b.subarray(0, 16).equals(Buffer.from('SQLite format 3\0'))) return { format: 'sqlite', basis: 'magic-only; schema validation pending' };
  if (starts([100, 101, 120, 10])) return { format: 'android-dex', basis: 'magic-only; header validation pending' };
  if (starts([71, 71, 85, 70])) return { format: 'model-gguf', basis: 'magic-only; tensor validation pending' };
  if (b.subarray(0, 8).equals(Buffer.from('bplist00'))) return { format: 'apple-plist', basis: 'magic-only; trailer validation pending' };
  if (starts([0xca, 0xfe, 0xba, 0xbe])) return { format: 'jvm-class-or-fat-macho', basis: 'ambiguous magic; structural validation required' };
  if ([[0xfe,0xed,0xfa,0xce],[0xce,0xfa,0xed,0xfe],[0xfe,0xed,0xfa,0xcf],[0xcf,0xfa,0xed,0xfe]].some(m => starts(m))) {
    return { format: 'native-macho', basis: 'magic-only; structural validation pending' };
  }
  if ([[0xd4,0xc3,0xb2,0xa1],[0xa1,0xb2,0xc3,0xd4],[0x0a,0x0d,0x0d,0x0a]].some(m => starts(m))) {
    return { format: 'pcap-capture', basis: 'magic-only; packet validation pending' };
  }
  return { format: 'unknown', basis: 'No validated format identification; extensions are not evidence' };
}
