import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readdir, readFile, writeFile, symlink, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { watch } from 'node:fs';
import { AnalysisService } from '../dist/service.js';

const sha = value => createHash('sha256').update(value).digest('hex');
const source = 'export function answer(){return 6*7;}\n';
const expected = 'export function answer(){return 42;}\n';
async function fixture(t, limits) {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-sidecar-'));
  const workspace = path.join(root, 'workspace'); await mkdir(workspace);
  const file = path.join(root, 'source.mjs'); await writeFile(file, source);
  const service = await AnalysisService.create({ roots: [root], workspace, limits });
  t.after(() => service.close());
  return { root, workspace, file, service };
}
const prepare = (service, file, options) => service.run('prepare_javascript_view', { path: file }, options);

test('sidecar default scope denies before a missing target read and exposes no write operation', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-sidecar-denied-'));
  const service = await AnalysisService.create({ roots: [root] }); t.after(() => service.close());
  const caps = await service.run('capabilities', {});
  assert.equal(caps.analysisWrites, false);
  assert.ok(!caps.operations.includes('prepare_javascript_view'));
  const denied = await prepare(service, path.join(root, 'absent.mjs'));
  assert.equal(denied.reason.code, 'workspace_required');
  assert.deepEqual(await readdir(root), []);
});

test('sidecar writes exact independently expected arithmetic bytes, bounded evidence, unique files and unchanged source', async t => {
  const { service, file, workspace } = await fixture(t);
  const caps = await service.run('capabilities', {});
  assert.equal(caps.analysisWrites, true);
  assert.equal(caps.writeScope.workspace, workspace);
  assert.ok(caps.operations.includes('prepare_javascript_view'));
  const first = await prepare(service, file);
  assert.equal(first.status, 'ok', JSON.stringify(first));
  assert.equal(first.behavioralEquivalence, 'unknown');
  assert.equal(first.sidecar.completion, 'complete');
  assert.equal(path.dirname(first.sidecar.viewDirectory), workspace);
  assert.match(path.basename(first.sidecar.viewDirectory), /^anti-bla-view-/);
  assert.equal(first.sidecar.viewPath, path.join(first.sidecar.viewDirectory, 'inspection.mjs'));
  assert.equal(first.sidecar.evidencePath, path.join(first.sidecar.viewDirectory, 'evidence.json'));
  assert.equal(await readFile(first.sidecar.viewPath, 'utf8'), expected);
  assert.equal(first.sidecar.derivativeSha256, sha(expected));
  assert.equal(first.sidecar.originalSha256, sha(source));
  const manifestBytes = await readFile(first.sidecar.evidencePath);
  const evidence = JSON.parse(manifestBytes);
  assert.ok(manifestBytes.length <= 65536);
  assert.equal(evidence.derivative.sha256, sha(expected));
  assert.equal(evidence.original.sha256, sha(source));
  assert.equal(evidence.scope, 'inspection-only');
  assert.equal(evidence.fullEquivalence, 'UNKNOWN');
  assert.equal(evidence.selection.assumeStandardIntrinsics, false);
  assert.equal(evidence.changeMap.total, 1);
  assert.match(evidence.changeMap.sha256, /^[a-f0-9]{64}$/);
  assert.match(evidence.analysisIdentity.implementationSha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isFinite(Date.parse(evidence.createdAt)));
  assert.equal(first.sidecar.evidenceSha256, sha(manifestBytes));
  const second = await prepare(service, file);
  assert.equal(second.status, 'ok');
  assert.notEqual(first.sidecar.viewDirectory, second.sidecar.viewDirectory);
  assert.equal(await readFile(first.sidecar.evidencePath, 'utf8'), manifestBytes.toString());
  assert.equal(await readFile(file, 'utf8'), source);
  assert.equal((await readdir(workspace)).length, 2);
  assert.ok(!JSON.stringify(first).includes(expected));
});

test('sidecar malformed, eval and with inputs produce UNKNOWN without any output files', async t => {
  const { service, file, workspace } = await fixture(t);
  for (const code of ['export function {', 'export function f(){eval("var x=1");return x}', 'exports.f=function(o){with(o){return x}}']) {
    await writeFile(file, code);
    const r = await prepare(service, file);
    assert.equal(r.status, 'unknown', JSON.stringify(r));
    assert.deepEqual(await readdir(workspace), []);
  }
});

test('sidecar validates explicit workspace and source paths without following links', async t => {
  const { root, workspace, file, service } = await fixture(t);
  for (const invalid of [file, path.join(root, 'missing'), '\\\\server\\share']) {
    await assert.rejects(() => AnalysisService.create({ roots: [root], workspace: invalid }));
  }
  const alias = path.join(root, 'alias'); await symlink(workspace, alias, 'junction');
  await assert.rejects(() => AnalysisService.create({ roots: [root], workspace: alias }));
  const outside = await mkdtemp(path.join(tmpdir(), 'anti-bla-sidecar-outside-'));
  const external = path.join(outside, 'source.mjs'); await writeFile(external, source);
  assert.equal((await prepare(service, external)).reason.code, 'outside_root');
  assert.equal((await prepare(service, path.join(outside, 'absent.mjs'))).reason.code, 'outside_root');
  const inputAlias = path.join(root, 'input-alias'); await symlink(root, inputAlias, 'junction');
  assert.equal((await prepare(service, path.join(inputAlias, 'source.mjs'))).status, 'error');
  assert.deepEqual(await readdir(workspace), []);
});

test('sidecar refuses changed workspace identity before writing', async t => {
  const { root, workspace, file, service } = await fixture(t);
  await rename(workspace, path.join(root, 'old-workspace')); await mkdir(workspace);
  const r = await prepare(service, file);
  assert.equal(r.status, 'unknown');
  assert.equal(r.reason.code, 'workspace_changed');
  assert.deepEqual(await readdir(workspace), []);
});

test('sidecar canonicalizes a valid explicit workspace before persisting parent identities', async t => {
  const { root, workspace, file } = await fixture(t);
  const spelling = process.platform === 'win32' ? workspace.toUpperCase() : path.join(workspace, '..', 'workspace');
  const service = await AnalysisService.create({roots:[root],workspace:spelling}); t.after(() => service.close());
  const result = await prepare(service, file);
  assert.equal(result.status, 'ok', JSON.stringify(result));
  assert.equal(path.dirname(result.sidecar.viewDirectory), workspace);
});

test('sidecar counts unfinished managed entries across service restarts and never prunes them', async t => {
  const { root, workspace, file, service } = await fixture(t);
  for (let n = 0; n < 128; n++) await mkdir(path.join(workspace, `anti-bla-view-pending-${n}`));
  const restarted = await AnalysisService.create({ roots: [root], workspace }); t.after(() => restarted.close());
  for (const s of [service, restarted]) {
    const r = await prepare(s, file);
    assert.equal(r.status, 'unknown'); assert.equal(r.reason.code, 'workspace_entry_limit');
  }
  assert.equal((await readdir(workspace)).length, 128);
});

test('sidecar scan and stale reservation are bounded, preserve unrelated entries and fail closed', async t => {
  const { service, workspace, file } = await fixture(t);
  const lock = path.join(workspace, '.anti-bla-views.lock'); await writeFile(lock, 'operator-owned-do-not-touch');
  const r = await prepare(service, file);
  assert.equal(r.status, 'unknown'); assert.equal(r.reason.code, 'workspace_busy');
  assert.equal(await readFile(lock, 'utf8'), 'operator-owned-do-not-touch');
});

test('sidecar low output budget and pre-cancellation leave no view and deadline never reports completion', async t => {
  const f = await fixture(t, { maxOutputBytes: 1024 });
  const r = await prepare(f.service, f.file);
  assert.equal(r.status, 'unknown'); assert.equal(r.reason.code, 'output_limit');
  assert.deepEqual(await readdir(f.workspace), []);
  const aborted = new AbortController(); aborted.abort();
  assert.equal((await prepare(f.service, f.file, { signal: aborted.signal })).reason.code, 'cancelled');
  const timed = await AnalysisService.create({ roots: [f.root], workspace: f.workspace, limits: { timeoutMs: 1 } });
  t.after(() => timed.close());
  const timeout = await prepare(timed, f.file);
  assert.equal(timeout.status, 'unknown'); assert.equal(timeout.reason.code, 'deadline');
  assert.equal(timeout.sidecar.completion, 'unknown');
  assert.ok(path.isAbsolute(timeout.sidecar.viewDirectory));
});

test('sidecar refuses source over the derivative admission cap and arbitrary output parameters', async t => {
  const { service, file, workspace } = await fixture(t);
  await writeFile(file, '/*' + 'x'.repeat(8 * 1024 * 1024) + '*/');
  const r = await prepare(service, file);
  assert.equal(r.status, 'unknown');
  assert.deepEqual(await readdir(workspace), []);
  assert.equal((await service.run('prepare_javascript_view', { path: file, outputPath: file })).reason.code, 'invalid_request');
});

test('sidecar caps expanded derivative bytes independently of the admitted input size', async t => {
  const { service, file, workspace } = await fixture(t);
  const code = `const text=${JSON.stringify('x'.repeat(65500))};export function f(sink){${'sink(text);'.repeat(130)}}`;
  assert.ok(Buffer.byteLength(code) < 100000);
  await writeFile(file, code);
  const r = await prepare(service, file);
  assert.equal(r.status, 'unknown'); assert.equal(r.reason.code, 'derivative_limit');
  assert.deepEqual(await readdir(workspace), []);
});

test('sidecar streams bounded workspace names without following or deleting unrelated entries', async t => {
  const { service, file, workspace } = await fixture(t);
  for (let n = 0; n < 4096; n++) await writeFile(path.join(workspace, `unrelated-${n}`), 'keep');
  const r = await prepare(service, file);
  assert.equal(r.status, 'unknown'); assert.equal(r.reason.code, 'workspace_scan_limit');
  assert.equal((await readdir(workspace)).length, 4096);
  assert.equal(await readFile(path.join(workspace, 'unrelated-0'), 'utf8'), 'keep');
});

test('sidecar concurrent independent services never exceed the cross-restart managed bound', async t => {
  const { root, service, file, workspace } = await fixture(t);
  for (let n = 0; n < 127; n++) await mkdir(path.join(workspace, `anti-bla-view-incomplete-${n}`));
  const other = await AnalysisService.create({ roots: [root], workspace }); t.after(() => other.close());
  const results = await Promise.all([prepare(service, file), prepare(other, file)]);
  assert.equal(results.filter(r => r.status === 'ok').length, 1, JSON.stringify(results));
  assert.ok(results.some(r => ['workspace_busy', 'workspace_entry_limit'].includes(r.reason?.code)));
  assert.equal((await readdir(workspace)).filter(name => name.startsWith('anti-bla-view-')).length, 128);
});

test('sidecar cancellation after reservation returns UNKNOWN locator and never reports a complete handoff', async t => {
  const { service, file, workspace } = await fixture(t);
  const controller = new AbortController();
  let observedDirectory;
  const watcher = watch(workspace, (_event, name) => {
    if (name?.toString().startsWith('anti-bla-view-')) { observedDirectory = name.toString(); controller.abort(); }
  });
  t.after(() => watcher.close());
  const r = await prepare(service, file, { signal: controller.signal });
  assert.ok(observedDirectory);
  assert.equal(r.status, 'unknown'); assert.equal(r.reason.code, 'cancelled');
  assert.equal(r.sidecar.completion, 'unknown'); assert.equal(r.sidecar.handoffAllowed, false);
  assert.equal(path.basename(r.sidecar.viewDirectory), observedDirectory);
  assert.ok((await readdir(workspace)).includes(observedDirectory));
});

test('sidecar enabled capabilities still respect the configured result cap for long workspace paths', async t => {
  const {root, workspace} = await fixture(t);
  const nested = path.join(workspace, 'a'.repeat(100), 'b'.repeat(100)); await mkdir(nested, {recursive:true});
  const service = await AnalysisService.create({roots:[root],workspace:nested,limits:{maxOutputBytes:1024}}); t.after(() => service.close());
  const r = await service.run('capabilities', {});
  assert.ok(Buffer.byteLength(JSON.stringify(r)) <= 1024);
  assert.equal(r.status, 'unknown'); assert.equal(r.reason.code, 'output_limit');
  assert.deepEqual(await readdir(nested), []);
});
