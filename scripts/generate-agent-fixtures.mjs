import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { protectTarget } from '../research/bla/dist/engine/protector.js';

// Owned randomized fixtures for artifact-only agent trials. Never import or run
// an emitted fixture on the host. Expected answers stay in the judge directory.
const root = path.resolve(import.meta.dirname, '..');
const stamp = new Date().toISOString().replaceAll(':', '-');
const work = path.join(root, 'scratch', 'agent-evaluation', stamp);
const judge = path.join(work, 'judge');
await mkdir(judge, { recursive: true });
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const identity = async file => { const bytes = await readFile(file); return { path: file, bytes: bytes.length, sha256: sha(bytes) }; };
const report = { schema: 'anti-bla.agent-fixtures/1', generatedUtc: new Date().toISOString(), work,
  provenance: 'New independently authored randomized fixtures; no upstream tests/challenge or earlier recovery answers',
  task: { export: 'attachRoutes', receiver: 'first parameter', method: 'put', arguments: [0, 1] },
  assumptions: ['Unmodified standard JavaScript intrinsics', 'Only these owned fixtures may run in the recorded disposable Docker profile'],
  trials: [], lanes: [], targetExecutionDuringGeneration: false };
const runner = `import {readFile} from 'node:fs/promises';
const rows=[];
const subject=await import('./index.mjs');
subject.attachRoutes({put:(...args)=>{rows.push(args);return undefined;}});
const status=await readFile('/proc/self/status','utf8');
console.log(JSON.stringify({schema:'owned-agent-runtime/1',selectedExport:'attachRoutes',method:'put',calls:rows,
containment:Object.fromEntries(status.split('\\n').filter(s=>/^(NoNewPrivs|Seccomp|CapEff|CapPrm|CapBnd):/.test(s)).map(s=>s.split(/:\\s*/)))}));
`;
for (let index = 1; index <= 4; index++) {
  const token = randomBytes(8).toString('hex');
  const scalar = randomBytes(2).readUInt16LE() % 89 + 11;
  const extra = randomBytes(2).readUInt16LE() % 199;
  const source = `const first="/v3/";\nconst group="${token}";\nexport function attachRoutes(transport){\n const endpoint=first+group+"/events";\n const attempts=${scalar}*3+${extra};\n transport.put(endpoint,attempts);\n}\n` + (index === 4 ? Array.from({ length: 300 }, (_, n) => `export function ordinary_${n}(value){return value+${n};}\n`).join('') : '');
  const original = path.join(judge, `original-${index}.mjs`);
  await writeFile(original, source, { flag: 'wx' });
  const originalIdentity = await identity(original);
  const protectedFile = path.join(judge, `protected-${index}.mjs`);
  const seed = `anti-bla-agent-heldout-${index}-${randomBytes(6).toString('hex')}`;
  const startedUtc = new Date().toISOString(), start = performance.now();
  const emission = index === 4 ? null : protectTarget({ inputPath: original, outputPath: protectedFile, seed, intensity: 'balanced', runtimeDeception: true });
  if (index === 4) await copyFile(original, protectedFile);
  assert.equal((await identity(original)).sha256, originalIdentity.sha256);
  report.trials.push({ index, kind: index === 4 ? 'benign-complexity-control' : 'actual-protected-heldout', seed,
    original: originalIdentity, protected: await identity(protectedFile), expected: { endpoint: `/v3/${token}/events`, amount: scalar * 3 + extra },
    emitter: emission === null ? null : { call: 'protectTarget', options: { seed, intensity: 'balanced', runtimeDeception: true },
      startedUtc, wallMs: performance.now() - start, result: emission } });
}
for (const lane of ['clean-rea', 'protected-rea', 'protected-anti-rea']) {
  const laneRoot = path.join(work, lane);
  await mkdir(laneRoot);
  const manifest = { schema: 'anti-bla.agent-lane/1', lane, laneRoot, inputs: [],
    task: report.task, assumptions: report.assumptions, maxAnalysisCommands: 40,
    scope: 'Selected two-argument task only; not full semantics or universal agent defeat' };
  for (const row of report.trials) {
    const inputDirectory = path.join(laneRoot, `case-${row.index}`, 'input');
    await mkdir(inputDirectory, { recursive: true });
    const file = path.join(inputDirectory, 'index.mjs');
    await copyFile(lane === 'clean-rea' ? row.original.path : row.protected.path, file);
    await writeFile(path.join(inputDirectory, 'runner.mjs'), runner, { flag: 'wx' });
    manifest.inputs.push({ index: row.index, kind: row.kind, inputDirectory, artifact: await identity(file), runner: await identity(path.join(inputDirectory, 'runner.mjs')) });
  }
  const manifestPath = path.join(laneRoot, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  report.lanes.push({ lane, manifest: await identity(manifestPath) });
}
const reportPath = path.join(judge, 'expected.json');
await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ work, manifests: report.lanes.map(lane => lane.manifest.path), judge: reportPath, generated: 3, benignControls: 1 }));
