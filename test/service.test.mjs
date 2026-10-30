import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, mkdir, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { AnalysisService } from '../dist/service.js';
import { validateLocalPath } from '../dist/artifacts.js';
const packageVersion = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version;

// Catches wrong hashing, path admission, boundary/range validation, taint loss,
// target execution/writes, limits and cancellation; expectations are literal.
async function fixture(bytes = Buffer.from('abc'), limits = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-test-'));
  const target = path.join(root, 'input.bin');
  await writeFile(target, bytes);
  const service = await AnalysisService.create({ roots: [root], limits });
  return { root, target, service };
}

test('identity uses the complete original bytes and retains untrusted provenance', async () => {
  const { target, service } = await fixture();
  const r = await service.run('inspect_artifact', { path: target });
  assert.equal(r.status, 'ok');
  assert.equal(r.artifact.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(r.artifact.bytes, 3);
  assert.equal(r.provenance.trust, 'untrusted-artifact');
  assert.equal(r.provenance.originalSha256, r.artifact.sha256);
  assert.equal(r.behavioralEquivalence, 'unknown');
  assert.match(r.evidenceId, /^[a-f0-9]{64}$/);
});

test('byte views use UTF-8 byte coordinates, not UTF-16 character offsets', async () => {
  const { target, service } = await fixture(Buffer.from('A€Z'));
  const r = await service.run('read_artifact_view', { path: target, offset: 1, length: 3 });
  assert.equal(r.status, 'ok');
  assert.equal(r.view.base64, '4oKs');
  assert.deepEqual(r.view.range, { offset: 1, length: 3 });
  assert.equal(r.view.inspectionOnly, true);
  assert.equal(r.provenance.originalSha256, createHash('sha256').update('A€Z').digest('hex'));
});

test('reading an apparent script never executes it or writes alongside input', async () => {
  const { root, target, service } = await fixture(Buffer.from('import "node:fs"; throw Error("must not run");'));
  const before = await readdir(root);
  const original = await readFile(target);
  const r = await service.run('inspect_artifact', { path: target });
  assert.equal(r.status, 'ok');
  assert.deepEqual(await readdir(root), before);
  assert.deepEqual(await readFile(target), original);
});

test('outside-root files, traversal and directories are refused', async () => {
  const { root, service } = await fixture();
  const outside = await mkdtemp(path.join(tmpdir(), 'anti-bla-outside-'));
  await writeFile(path.join(outside, 'secret'), 'out of scope');
  for (const candidate of [path.join(outside, 'secret'), path.join(root, '..', path.basename(outside), 'secret'), root]) {
    const r = await service.run('inspect_artifact', { path: candidate });
    assert.equal(r.status, 'error');
    assert.ok(['outside_root', 'not_regular_file'].includes(r.reason.code));
    assert.equal(r.artifact, undefined);
  }
});

test('a junction resolving outside the allowed root is refused', async () => {
  const { root, service } = await fixture();
  const outside = await mkdtemp(path.join(tmpdir(), 'anti-bla-link-outside-'));
  await writeFile(path.join(outside, 'secret'), 'out of scope');
  await symlink(outside, path.join(root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
  const r = await service.run('inspect_artifact', { path: path.join(root, 'escape', 'secret') });
  assert.equal(r.status, 'error');
  assert.equal(r.reason.code, 'outside_root');
});

test('missing file and unsupported tools fail closed', async () => {
  const { root, target, service } = await fixture();
  assert.equal((await service.run('inspect_artifact', { path: path.join(root, 'absent') })).status, 'error');
  assert.equal((await service.run('run_shell', { path: target })).reason.code, 'invalid_request');
});

test('strict schemas reject extra arguments, invalid offsets, oversized views and missing paths', async () => {
  const { target, service } = await fixture();
  for (const args of [{ path: target, execute: true }, {}, { path: 3 }, { path: target, offset: -1 }, { path: target, length: 4097 }]) {
    const op = 'offset' in args || 'length' in args ? 'read_artifact_view' : 'inspect_artifact';
    assert.equal((await service.run(op, args)).reason.code, 'invalid_request');
  }
  const beyond = await service.run('read_artifact_view', { path: target, offset: 4, length: 1 });
  assert.equal(beyond.status, 'error');
  assert.equal(beyond.reason.code, 'invalid_range');
});

test('input and output exhaustion are UNKNOWN, bounded, and never a bypass', async () => {
  const tiny = await fixture(Buffer.alloc(32), { maxInputBytes: 16 });
  const tooBig = await tiny.service.run('inspect_artifact', { path: tiny.target });
  assert.equal(tooBig.status, 'unknown');
  assert.equal(tooBig.reason.code, 'input_limit');
  const output = await fixture(Buffer.alloc(2048, 65), { maxOutputBytes: 2048 });
  const r = await output.service.run('read_artifact_view', { path: output.target, length: 2048 });
  assert.equal(r.status, 'unknown');
  assert.equal(r.reason.code, 'output_limit');
  assert.ok(Buffer.byteLength(JSON.stringify(r)) <= 2048);
});

test('pre-cancelled and deadline-limited requests leave the service usable', async () => {
  const { target, service } = await fixture();
  const controller = new AbortController();
  controller.abort();
  const r = await service.run('inspect_artifact', { path: target }, { signal: controller.signal });
  assert.equal(r.status, 'unknown');
  assert.equal(r.reason.code, 'cancelled');
  const slow = await fixture(Buffer.alloc(1024 * 1024), { timeoutMs: 1 });
  const deadline = await slow.service.run('inspect_artifact', { path: slow.target });
  assert.equal(deadline.status, 'unknown');
  assert.equal(deadline.reason.code, 'deadline');
  assert.equal((await service.run('inspect_artifact', { path: target })).status, 'ok');
});

test('invalid service roots and limits are rejected before any analysis', async () => {
  const { root } = await fixture();
  await assert.rejects(() => AnalysisService.create({ roots: [] }));
  await assert.rejects(() => AnalysisService.create({ roots: [root], limits: { maxInputBytes: 0 } }));
  await assert.rejects(() => AnalysisService.create({ roots: [root], limits: { timeoutMs: Infinity } }));
});

test('mixed-separator UNC namespaces are refused before filesystem or network access', () => {
  for (const candidate of ['\\\\server\\share\\file', '//server/share/file', '\\/server/share/file', '/\\server/share/file']) {
    assert.throws(() => validateLocalPath(candidate), { code: 'unsupported_path' });
  }
});

test('high-bit binary bytes cannot impersonate an ASCII format magic', async () => {
  const { target, service } = await fixture(Buffer.from('e2f0ece9f3f4b0b0', 'hex'));
  const r = await service.run('inspect_artifact', { path: target });
  assert.equal(r.identification.format, 'unknown');
  const real = await fixture(Buffer.from('bplist00'));
  assert.equal((await real.service.run('inspect_artifact', { path: real.target })).identification.format, 'apple-plist');
});

test('evidence binds the producing tool/runtime and does not imply equivalence', async () => {
  const { target, service } = await fixture();
  const r = await service.run('inspect_artifact', { path: target });
  assert.equal(r.analysisIdentity.tool, 'anti-bla');
  assert.equal(r.analysisIdentity.version, packageVersion);
  assert.equal(r.analysisIdentity.node, process.version);
  assert.ok(r.analysisIdentity.implementationModules.includes('formats/wasm.js'));
  assert.equal(r.evidence.limits.maxInputBytes, 64 * 1024 * 1024);
  assert.equal(r.evidence.input, r.artifact.sha256);
  assert.equal(createHash('sha256').update(JSON.stringify(r.evidence)).digest('hex'), r.evidenceId);
  assert.equal(r.behavioralEquivalence, 'unknown');
});
