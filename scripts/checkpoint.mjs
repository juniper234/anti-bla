import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { execFileSync, spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

// Qualification harness only. It runs our compiler/tests, never an artifact.
const root = path.resolve(import.meta.dirname, '..');
process.chdir(root);
const sha = data => createHash('sha256').update(data).digest('hex');
const fileIdentity = async file => ({ path: file, sha256: sha(await readFile(file)) });
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
const stamp = new Date().toISOString().replaceAll(':', '-');
const checkpoint = process.argv.includes('--final') ? 'C8-local-distribution' : 'C0-C2-core';
await mkdir('reports/checkpoints', { recursive: true });

async function run(args, name) {
  const log = `reports/checkpoints/${stamp}-${name}.log`;
  const output = createWriteStream(log, { flags: 'wx' });
  const start = performance.now();
  const child = spawn(process.execPath, args, { cwd: root, stdio: ['ignore','pipe','pipe'] });
  child.stdout.pipe(output, { end: false });
  child.stderr.pipe(output, { end: false });
  const exit = await new Promise((resolve, reject) => { child.once('exit', resolve); child.once('error', reject); });
  await new Promise(resolve => output.end(resolve));
  return { command: [process.execPath, ...args], exit, elapsedMs: performance.now() - start, log, peakMemoryBytes: null };
}

const inventory = JSON.parse(await readFile('docs/shield-inventory.json', 'utf8'));
const expected = git('-C','research/bla','ls-files','src/shields').split(/\r?\n/).sort();
const actual = inventory.files.map(f => f.path).sort();
if (JSON.stringify(expected) !== JSON.stringify(actual)) throw Error('Shield inventory incomplete');
for (const file of inventory.files) {
  if (sha(await readFile(`research/bla/${file.path}`)) !== file.sha256) throw Error(`Source hash mismatch: ${file.path}`);
}
const build = await run(['node_modules/typescript/bin/tsc','-p','tsconfig.json'], 'build');
const tests = (await readdir('test')).filter(f => f.endsWith('.test.mjs')).sort().map(f => `test/${f}`);
const regression = build.exit === 0 ? await run(['--test', ...tests], 'regression') : null;
const sourceFiles = (await readdir('src', {recursive:true})).filter(f => f.endsWith('.ts')).sort().map(f => `src/${f.replaceAll('\\','/')}`);
const report = {
  schema: 1, checkpoint, generatedAt: new Date().toISOString(),
  status: build.exit === 0 && regression?.exit === 0 ? 'REGRESSION_VERIFIED' : 'FAIL',
  tools: { node: {version: process.version, executable: process.execPath},
    sdk: JSON.parse(await readFile('node_modules/@modelcontextprotocol/sdk/package.json','utf8')).version,
    typescript: JSON.parse(await readFile('node_modules/typescript/package.json','utf8')).version,
    dependencies: await fileIdentity('package-lock.json') },
  upstreams: Object.fromEntries(await Promise.all(['bla','rea'].map(async name => [name, {
    sha: git('-C', `research/${name}`, 'rev-parse', 'HEAD'),
    package: JSON.parse(await readFile(`research/${name}/package.json`, 'utf8')).version,
    license: await fileIdentity(`research/${name}/LICENSE`),
  }]))),
  inventory: { files: actual.length, exactPathsAndHashes: true, manifest: await fileIdentity('docs/shield-inventory.json') },
  sourceIdentity: await Promise.all(sourceFiles.map(fileIdentity)), testIdentity: await Promise.all(tests.map(fileIdentity)),
  runs: [build, regression].filter(Boolean),
  fixtureInputs: [
    { origin: 'independent literal in service/MCP tests', seed: null, bytes: 3, sha256:'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', expected:'Complete original identity; no target execution/writes' },
    { origin: 'independent literal UTF8 A-euro-Z', seed: null, bytes:5, sha256:sha(Buffer.from('A€Z')), expected:'Byte offset1 length3 gives base64 4oKs' },
    { origin: 'independent malformed high-bit bplist lookalike', seed:null, bytes:8, sha256:sha(Buffer.from('e2f0ece9f3f4b0b0','hex')), expected:'unknown format' },
  ],
  behavioralRecoveryAssertion: 'NONE: infrastructure and inert byte/pattern views only; no BLA semantic bypass claimed',
  normalControlResult: regression?.exit === 0 ? 'Literal identity/byte views and benign role/security lookalikes pass in regression' : 'FAIL_OR_UNKNOWN',
  knownLimits: ['Hostile concurrent filesystem writers are outside the OS sandbox guarantee', 'Pattern index is incomplete by design and never a safety verdict', 'Dynamic/protected semantic recovery qualification still required', 'Peak child memory and agent usage/cost not instrumented'],
  rejectedAttempts: 'reports/FAILURES.jsonl and C1/C2 RED logs',
  nextAction: process.argv.includes('--final') ? 'Read independent reviews, scoped qualification index and separate installed-package verification; this regression checkpoint alone is not all-family recovery' : 'C3 JS semantic recovery; C4 independent ASAR; C5/C6 remaining formats; C7-C9 qualification/review/package',
};
const destination = `reports/checkpoints/${stamp}-${checkpoint}.json`;
await writeFile(destination, JSON.stringify(report, null, 2)+'\n', { flag: 'wx' });
console.log(JSON.stringify({ report: destination, status: report.status, inventory: actual.length, buildExit:build.exit, regressionExit:regression?.exit }));
process.exitCode = report.status === 'REGRESSION_VERIFIED' ? 0 : 1;
