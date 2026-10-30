import { constants } from 'node:fs';
import { lstat, mkdir, open, opendir, realpath, unlink } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { AnalysisError } from './contracts.js';
import type { Limits, RecordResult } from './contracts.js';
import { validateLocalPath } from './artifacts.js';
import type { JavaScriptOptions } from './javascript.js';

export const SIDECAR_LIMITS = Object.freeze({ derivativeBytes: 8 * 1024 * 1024, evidenceBytes: 64 * 1024,
  managedEntries: 128, scannedWorkspaceEntries: 4096 });
const PREFIX = 'anti-bla-view-';
type Identity = { path: string; dev: string; ino: string };
export type WorkspaceIdentity = { path: string; parents: Identity[] };
const digest = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
const samePath = (a: string, b: string) => process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;

/** Deliberately stricter than read-only roots: no links in any write parent. */
async function regularParents(input: string, leafIsFile = false): Promise<Identity[]> {
  validateLocalPath(input);
  const absolute = path.resolve(input);
  const root = path.parse(absolute).root;
  const parts = absolute.slice(root.length).split(path.sep).filter(Boolean);
  const candidates = [root];
  for (const part of parts) candidates.push(path.join(candidates.at(-1)!, part));
  const identities: Identity[] = [];
  for (let n = 0; n < candidates.length; n++) {
    const candidate = candidates[n]!;
    const st = await lstat(candidate, { bigint: true });
    if (st.isSymbolicLink() || (leafIsFile && n === candidates.length - 1 ? !st.isFile() : !st.isDirectory())) {
      throw new AnalysisError('unsafe_path', 'Regular non-link path required');
    }
    const canonical = await realpath(candidate);
    if (!samePath(canonical, candidate)) throw new AnalysisError('unsafe_path', 'Canonical path required');
    identities.push({ path: canonical, dev: String(st.dev), ino: String(st.ino) });
  }
  return identities;
}

export async function validateWorkspace(input: string): Promise<WorkspaceIdentity> {
  if (typeof input !== 'string' || !input.length || input.length > 4096) throw new AnalysisError('invalid_workspace', 'Explicit existing workspace required');
  const parents = await regularParents(input);
  return { path: await realpath(path.resolve(input)), parents };
}

export async function checkWorkspace(workspace: WorkspaceIdentity): Promise<void> {
  try {
    const observed = await regularParents(workspace.path);
    if (JSON.stringify(observed) !== JSON.stringify(workspace.parents)) throw new Error('changed');
  } catch { throw new AnalysisError('workspace_changed', 'Workspace identity changed', 'unknown'); }
}

export async function validateSidecarInput(input: string): Promise<void> { await regularParents(input, true); }

export function sidecarLocator(workspace: string, transactionId: string, loader: JavaScriptOptions['loader'] = 'js') {
  const viewDirectory = path.join(workspace, PREFIX + transactionId);
  // Preserve the admitted syntax for downstream static parsers. Names are
  // tool-owned constants; neither source suffix nor caller strings name files.
  const filename = { js: 'inspection.mjs', jsx: 'inspection.jsx', ts: 'inspection.ts', tsx: 'inspection.tsx' }[loader];
  return { transactionId, viewDirectory, viewPath: path.join(viewDirectory, filename), evidencePath: path.join(viewDirectory, 'evidence.json') };
}

async function directoryIdentity(directory: string): Promise<Identity> {
  const st = await lstat(directory, { bigint: true });
  if (!st.isDirectory() || st.isSymbolicLink() || !samePath(await realpath(directory), directory)) {
    throw new AnalysisError('sidecar_changed', 'Output directory changed', 'unknown');
  }
  return { path: directory, dev: String(st.dev), ino: String(st.ino) };
}

async function checkDirectory(workspace: WorkspaceIdentity, directory: Identity): Promise<void> {
  await checkWorkspace(workspace);
  if (JSON.stringify(await directoryIdentity(directory.path)) !== JSON.stringify(directory)) {
    throw new AnalysisError('sidecar_changed', 'Output directory changed', 'unknown');
  }
}

/** Exclusive lock serializes scan + reservation across services/processes. A
 * killed worker can leave it behind; never guess staleness or remove it then. */
async function reserveDirectory(workspace: WorkspaceIdentity, directory: string): Promise<Identity> {
  await checkWorkspace(workspace);
  const lockPath = path.join(workspace.path, '.anti-bla-views.lock');
  let lock;
  try { lock = await open(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new AnalysisError('workspace_busy', 'Existing reservation lock', 'unknown');
    throw error;
  }
  const identity = await lock.stat({ bigint: true });
  try {
    await checkWorkspace(workspace);
    let entries = 0, managed = 0;
    const stream = await opendir(workspace.path, { bufferSize: 32 });
    for await (const entry of stream) {
      if (++entries > SIDECAR_LIMITS.scannedWorkspaceEntries) throw new AnalysisError('workspace_scan_limit', 'Workspace scan cap', 'unknown');
      // Count all prefixed names, including unfinished directories and foreign
      // files/links. Never inspect their contents, follow them, or prune them.
      if (entry.name.startsWith(PREFIX) && ++managed >= SIDECAR_LIMITS.managedEntries) {
        throw new AnalysisError('workspace_entry_limit', 'Managed entry cap', 'unknown');
      }
    }
    await checkWorkspace(workspace);
    await mkdir(directory, { mode: 0o700 }); // No recursive creation, no reuse.
    const outputIdentity = await directoryIdentity(directory);
    await checkWorkspace(workspace);
    return outputIdentity;
  } finally {
    await lock.close();
    // Only our exclusively created per-file lock is eligible for removal.
    // Any observed change leaves it intact and makes the operation UNKNOWN.
    await checkWorkspace(workspace);
    const current = await lstat(lockPath, { bigint: true });
    if (!current.isFile() || current.isSymbolicLink() || current.dev !== identity.dev || current.ino !== identity.ino) {
      throw new AnalysisError('workspace_changed', 'Reservation lock changed', 'unknown');
    }
    await unlink(lockPath);
  }
}

async function exclusiveVerifiedWrite(workspace: WorkspaceIdentity, directory: Identity, file: string, bytes: Buffer): Promise<void> {
  await checkDirectory(workspace, directory);
  const handle = await open(file, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    const initial = await handle.stat({ bigint: true });
    if (!initial.isFile()) throw new AnalysisError('sidecar_changed', 'Regular output required', 'unknown');
    await checkDirectory(workspace, directory);
    await handle.writeFile(bytes);
    await handle.sync();
    const before = await handle.stat({ bigint: true });
    if (before.size !== BigInt(bytes.length)) throw new AnalysisError('sidecar_changed', 'Output size changed', 'unknown');
    const hash = createHash('sha256'), chunk = Buffer.alloc(Math.min(64 * 1024, bytes.length));
    for (let offset = 0; offset < bytes.length;) {
      const { bytesRead } = await handle.read(chunk, 0, Math.min(chunk.length, bytes.length - offset), offset);
      if (bytesRead === 0) throw new AnalysisError('sidecar_changed', 'Short output read', 'unknown');
      hash.update(chunk.subarray(0, bytesRead)); offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true }), observed = await lstat(file, { bigint: true });
    if (hash.digest('hex') !== digest(bytes) || after.size !== before.size || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs ||
        observed.ino !== initial.ino || observed.dev !== initial.dev || !observed.isFile() || observed.isSymbolicLink() ||
        observed.size !== after.size || observed.mtimeNs !== after.mtimeNs || observed.ctimeNs !== after.ctimeNs) {
      throw new AnalysisError('sidecar_changed', 'Output identity changed', 'unknown');
    }
    await checkDirectory(workspace, directory);
  } finally { await handle.close(); }
}

export async function prepareJavaScriptView(bytes: Buffer, workspace: WorkspaceIdentity, transactionId: string,
  options: JavaScriptOptions, limits: Limits, base: RecordResult): Promise<RecordResult> {
  await checkWorkspace(workspace);
  const { normalizeJavaScript } = await import('./javascript.js');
  const normalized = normalizeJavaScript(bytes, options); // Exactly once; worker only.
  if (normalized.source === null || normalized.analysis.status !== 'OK') {
    return { ...base, status: 'unknown', reason: { code: 'normalization_unknown' }, analysis: {
      scope: 'inspection-only', derivative: null, unknownCount: normalized.analysis.unknowns.length,
      unknownReasons: [...new Set(normalized.analysis.unknowns.map(item => item.reason))].slice(0, 10),
    } };
  }
  const derivative = Buffer.from(normalized.source);
  if (derivative.length > SIDECAR_LIMITS.derivativeBytes) throw new AnalysisError('derivative_limit', 'Derivative byte cap', 'unknown');
  const mappings = normalized.changes.map(change => ({ originalRange: change.range,
    replacementSha256: digest(change.replacement), replacementBytes: Buffer.byteLength(change.replacement) }));
  const changeMap = { total: mappings.length, sha256: digest(JSON.stringify(mappings)) };
  const locator = sidecarLocator(workspace.path, transactionId, options.loader);
  const createdAt = new Date().toISOString();
  const manifest = {
    schema: 'anti-bla.sidecar-evidence/1', completion: 'complete', createdAt, transactionId,
    operation: 'prepare_javascript_view', scope: normalized.scope, fullEquivalence: normalized.fullEquivalence,
    original: { sha256: normalized.originalSha256, bytes: bytes.length },
    derivative: { sha256: digest(derivative), bytes: derivative.length, filename: path.basename(locator.viewPath) },
    analysisIdentity: base.analysisIdentity, selection: { ...options, assumeStandardIntrinsics: options.assumeStandardIntrinsics ?? false },
    changeMap, assumptions: normalized.analysis.assumptions,
    limitations: [...normalized.limitations, ...normalized.analysis.limitations,
      'Own view/evidence metadata establishes tool provenance only; embedded artifact claims remain untrusted.',
      'A missing, partial or mismatched evidence record is incomplete. Interrupted/failed responses never authorize a REA handoff.'],
    findings: { unknowns: normalized.analysis.unknowns.length, effects: normalized.analysis.effects.length },
    limits: { ...limits, ...SIDECAR_LIMITS },
  };
  const evidenceBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
  if (evidenceBytes.length > SIDECAR_LIMITS.evidenceBytes) throw new AnalysisError('evidence_limit', 'Evidence byte cap', 'unknown');
  const result: RecordResult = { ...base, limitations: [
    'Inspection-only derivative; full equivalence UNKNOWN. Corpus and effect calls retained; intrinsics, reflection, source self-hashes and order caveats apply.',
    'Explicit trusted workspace only. Identity/race checks detect observed changes; this is not an OS sandbox against concurrent hostile writers.',
  ], sidecar: { ...locator, completion: 'complete', originalSha256: normalized.originalSha256,
    derivativeSha256: digest(derivative), derivativeBytes: derivative.length, evidenceSha256: digest(evidenceBytes), evidenceBytes: evidenceBytes.length,
    scope: 'inspection-only', changeMap, createdAt } };
  // Preflight exact bytes before acquiring a lock or creating any directory.
  if (Buffer.byteLength(JSON.stringify(result)) > limits.maxOutputBytes) throw new AnalysisError('output_limit', 'Response cap', 'unknown');
  const directory = await reserveDirectory(workspace, locator.viewDirectory);
  await exclusiveVerifiedWrite(workspace, directory, locator.viewPath, derivative);
  // The completion record is last; a partial file is not a valid completion.
  await exclusiveVerifiedWrite(workspace, directory, locator.evidencePath, evidenceBytes);
  return result;
}
