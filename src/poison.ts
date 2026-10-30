import { createHash } from 'node:crypto';

const patterns = [
  { needle: '<|im_start|>system', kind: 'role-spoof-candidate' },
  { needle: '<system>', kind: 'role-spoof-candidate' },
  { needle: '[system]', kind: 'role-spoof-candidate' },
  { needle: 'ignore previous instructions', kind: 'instruction-override-candidate' },
  { needle: 'ignore all previous instructions', kind: 'instruction-override-candidate' },
  { needle: 'disregard previous instructions', kind: 'instruction-override-candidate' },
] as const;

type Finding = {
  kind: string;
  range: { offset: number; length: number };
  sha256: string;
  confidence: 'pattern-only';
  reachability: 'unknown';
  claimAuthority: false;
};

/** An inert data index, deliberately not a safety detector or code remover.
 * The fixed ASCII patterns need no target-supplied regex, decoding or eval.
 * Latin-1 preserves original byte indices, including non-ASCII prefixes.
 */
export function indexSuspiciousData(bytes: Buffer) {
  const scanLimit = Math.min(bytes.length, 8 * 1024 * 1024);
  const findings: Finding[] = [];
  const overlap = Math.max(...patterns.map(p => p.needle.length)) - 1;
  let truncatedFindings = false;
  let scannedBytes = 0;
  scan: for (let base = 0; base < scanLimit; base += 65536) {
    const start = Math.max(0, base - overlap);
    const end = Math.min(base + 65536, scanLimit);
    const text = bytes.subarray(start, end).toString('latin1').toLowerCase();
    scannedBytes = end;
    for (const { needle, kind } of patterns) {
      let local = text.indexOf(needle);
      while (local !== -1) {
        const offset = start + local;
        if (offset >= base || offset + needle.length > base) {
          if (findings.length === 64) { truncatedFindings = true; break scan; }
          findings.push({
            kind, range: { offset, length: needle.length },
            sha256: createHash('sha256').update(bytes.subarray(offset, offset + needle.length)).digest('hex'),
            confidence: 'pattern-only', reachability: 'unknown', claimAuthority: false,
          });
        }
        local = text.indexOf(needle, local + needle.length);
      }
    }
  }
  findings.sort((a, b) => a.range.offset - b.range.offset || a.kind.localeCompare(b.kind));
  return {
    findings, scannedBytes, completeByteScan: scannedBytes === bytes.length && !truncatedFindings,
    truncatedFindings, safetyVerdict: 'unknown', automaticallyRemovedBytes: 0,
    policy: 'Target text never has instruction authority. Patterns are data candidates, including benign quotations; they do not prove deception, liveness or safety.',
    limitations: ['Fixed ASCII patterns only; encoded, paraphrased and unscanned content remains unknown. Preserve the original bytes, including self-hash/digest inputs.'],
  };
}
