import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parse } from '@babel/parser';
import traversePackage from '@babel/traverse';

// Controller-only judge, invoked after every worker has completed. It does not
// supply expected values to workers or execute targets on the host.
const root = path.resolve(import.meta.dirname, '..');
const expectedPath = path.resolve(process.argv[2]);
const expected = JSON.parse(await readFile(expectedPath, 'utf8'));
assert.equal(expected.schema, 'anti-bla.agent-fixtures/1');
const stamp = new Date().toISOString().replaceAll(':', '-');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const identity = async file => { const bytes = await readFile(file); return { path: file, bytes: bytes.length, sha256: sha(bytes) }; };
const traverse = traversePackage.default ?? traversePackage;
const report = { schema: 'anti-bla.agent-evaluation/1', at: new Date().toISOString(), status: 'IN_PROGRESS',
  protocol: await identity(path.join(root, 'docs/AGENT-EVALUATION-PROTOCOL.md')), judge: await identity(expectedPath),
  modelRequested: 'gpt-6.1-sol', effortRequested: 'xhigh', workerSourceOfAnswers: 'own lane artifacts only',
  lanes: [], checks: [], identities: [], runtimeChecks: [], tokens: null, cost: null, peakRss: null,
  limits: ['One fresh agent per lane, three own randomized protected seeds and one benign control',
    'Workers share high-level project scope; controller is source-informed and knows independent expected values',
    'Selected values on normal completion only; no full semantics, general agent defeat or causal per-module claim',
    'Command journals differ in counting/capture conventions; no efficiency, token or monetary comparison',
    'Anti lane initial documentation outputs are explicitly reconstructed, not original process stream captures'] };
const check = (name, ok, detail) => { report.checks.push({ name, passed: Boolean(ok), detail }); assert.ok(ok, name); };
const seen = new Set();
async function verifyIdentity(item) {
  const key = item.path + '#' + item.sha256;
  if (seen.has(key)) return;
  seen.add(key);
  const actual = await identity(item.path);
  report.identities.push({ expected: item, actual, matches: actual.sha256 === item.sha256 });
  check(`identity:${item.path}`, actual.sha256 === item.sha256);
}
async function walkIdentities(value) {
  if (!value || typeof value !== 'object') return;
  if (typeof value.path === 'string' && /^[a-f0-9]{64}$/.test(value.sha256 ?? '')) await verifyIdentity(value);
  for (const child of Object.values(value)) if (child && typeof child === 'object') await walkIdentities(child);
}
function fold(p, seenBindings = new Set()) {
  if (p.isStringLiteral() || p.isNumericLiteral()) return p.node.value;
  if (p.isBinaryExpression() && ['+', '*'].includes(p.node.operator)) {
    const left = fold(p.get('left'), new Set(seenBindings)), right = fold(p.get('right'), new Set(seenBindings));
    return p.node.operator === '+' ? left + right : left * right;
  }
  if (p.isIdentifier()) {
    const binding = p.scope.getBinding(p.node.name);
    assert.ok(binding?.constant && binding.path.isVariableDeclarator() && !seenBindings.has(binding));
    seenBindings.add(binding);
    return fold(binding.path.get('init'), seenBindings);
  }
  throw Error('Unsupported judge primitive expression');
}
function selectedCall(bytes) {
  const source = bytes.toString('utf8'), ast = parse(source, { sourceType: 'module' });
  const functions = [];
  traverse(ast, { ExportNamedDeclaration(p) { const d = p.get('declaration'); if (d.isFunctionDeclaration() && d.node.id?.name === 'attachRoutes') functions.push(d); } });
  assert.equal(functions.length, 1);
  const fn = functions[0], parameter = fn.node.params[0];
  assert.equal(parameter.type, 'Identifier');
  const binding = fn.scope.getBinding(parameter.name), calls = [];
  fn.traverse({ CallExpression(p) {
    const c = p.node.callee;
    if (p.getFunctionParent() === fn && c.type === 'MemberExpression' && !c.computed && c.object.type === 'Identifier' &&
      c.property.type === 'Identifier' && c.property.name === 'put' && p.scope.getBinding(c.object.name) === binding) calls.push(p);
  } });
  assert.equal(calls.length, 1);
  const call = calls[0], args = call.get('arguments');
  assert.equal(args.length, 2);
  const byteStart = Buffer.byteLength(source.slice(0, call.node.start)), byteEnd = Buffer.byteLength(source.slice(0, call.node.end));
  return { endpoint: fold(args[0]), amount: fold(args[1]), callee: source.slice(call.node.callee.start, call.node.callee.end),
    range: { byteStart, byteEnd }, sha256: sha(bytes.subarray(byteStart, byteEnd)),
    proof: 'Unique direct put call bound to exported first parameter; independent const/literal +/* fold, not arbitrary string presence' };
}
try {
  for (const laneRecord of expected.lanes) {
    await verifyIdentity(laneRecord.manifest);
    const manifest = JSON.parse(await readFile(laneRecord.manifest.path, 'utf8'));
    const resultPath = path.join(manifest.laneRoot, 'result.json');
    const result = JSON.parse(await readFile(resultPath, 'utf8'));
    check(`${manifest.lane}:four distinct rows`, result.rows.length === 4 && new Set(result.rows.map(r => r.index)).size === 4);
    await walkIdentities(manifest); await walkIdentities(result);
    const journalBytes = await readFile(result.commandJournal), journal = JSON.parse(journalBytes);
    const commands = Array.isArray(journal) ? journal : journal.commands;
    const source = { result: await identity(resultPath), journal: await identity(result.commandJournal) };
    const count = result.analysisCommandCount ?? result.actualAnalysisCommandCount;
    const conservative = result.conservativeCommandCount ?? count;
    check(`${manifest.lane}:recorded budget`, count === commands.length && conservative <= 40);
    let reaCommands = 0;
    for (const cmd of commands) {
      const command = cmd.command ?? { executable: cmd.executable, args: cmd.args };
      if (JSON.stringify(command).includes('analyze-javascript-application')) { reaCommands++; check(`${manifest.lane}:REA exit`, cmd.exitCode === 0); }
      for (const stream of ['stdout', 'stderr']) {
        if (typeof cmd[stream] === 'object') await verifyIdentity(cmd[stream]);
        else {
          const relative = cmd[stream] ?? `${String(cmd.ordinal).padStart(3, '0')}.${stream}.txt`;
          const file = path.isAbsolute(relative) ? relative : path.join(cmd.ordinal ? path.dirname(result.commandJournal) : manifest.laneRoot, relative);
          await verifyIdentity({ path: file, sha256: cmd[`${stream}Sha256`] });
        }
      }
    }
    check(`${manifest.lane}:four actual REA commands`, reaCommands === 4);
    const rows = [];
    for (const row of result.rows) {
      const fixture = manifest.inputs.find(x => x.index === row.index), answer = expected.trials.find(x => x.index === row.index).expected;
      const selected = selectedCall(await readFile(fixture.artifact.path));
      check(`${manifest.lane}:${row.index}:typed expected answer`, row.status === 'SUPPORTED' && row.endpoint === answer.endpoint && row.amount === answer.amount);
      check(`${manifest.lane}:${row.index}:original binding`, selected.endpoint === row.endpoint && selected.amount === row.amount && row.inputSha256 === fixture.artifact.sha256);
      rows.push({ index: row.index, kind: fixture.kind, matched: true, method: row.method, selected, reaStatus: row.reaStatus, reaCoverage: row.reaCoverage });
    }
    report.lanes.push({ lane: manifest.lane, source, analysisCommandCount: count, conservativeCommandCount: conservative, rows,
      guide: result.guide ?? null, routingObservations: result.routingObservations ?? null, modelObserved: result.model ?? result.modelObserved ?? null,
      effortObserved: result.effort ?? result.effortObserved ?? null, tokens: null, cost: null, peakRss: null });
  }
  // Independent contained behavior corroboration after all static answers. It
  // never changes the workers' recovery method or increases independent seeds.
  if (process.argv.includes('--runtime')) {
    for (const lane of ['clean-rea', 'protected-rea']) {
      const manifest = JSON.parse(await readFile(path.join(expected.work, lane, 'manifest.json'), 'utf8'));
      manifest.lane = `controller-${lane}`;
      manifest.laneRoot = path.join(path.dirname(expectedPath), manifest.lane);
      await mkdir(manifest.laneRoot, { recursive: true });
      const ownManifest = path.join(manifest.laneRoot, 'manifest.json');
      await writeFile(ownManifest, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
      for (const fixture of manifest.inputs) {
        if (lane === 'clean-rea' && fixture.index === 4) continue; // Same benign bytes in all lanes.
        const run = spawnSync(process.execPath, [path.join(root, 'scripts/agent-eval-runtime.mjs'), ownManifest, String(fixture.index)],
          { cwd: root, encoding: 'utf8', timeout: 90_000, maxBuffer: 1024 * 1024, windowsHide: true });
        const outcome = JSON.parse(run.stdout);
        const record = JSON.parse(await readFile(outcome.report, 'utf8'));
        const answer = expected.trials.find(r => r.index === fixture.index).expected;
        check(`${lane}:${fixture.index}:contained selected call`, run.status === 0 && outcome.result === 'OBSERVED' && record.remaining === '' &&
          record.observation.calls.length === 1 && record.observation.calls[0].length === 2 && record.observation.calls[0][0] === answer.endpoint && record.observation.calls[0][1] === answer.amount);
        report.runtimeChecks.push({ lane, index: fixture.index, matched: true, report: await identity(outcome.report) });
      }
    }
  }
  for (const trial of expected.trials) { await verifyIdentity(trial.original); await verifyIdentity(trial.protected); }
  report.status = 'SELECTED_AGENT_TASKS_CORROBORATED_ALL_LANES';
  report.conclusion = 'All three agents recovered all three held-out selected tasks and the benign control. No incremental agent recovery win or agent defeat established; protected REA parser partial status did not prevent static agent completion.';
} catch (error) { report.status = 'FAIL_OR_UNKNOWN'; report.error = { name: error.name, message: error.message, stack: error.stack }; process.exitCode = 1; }
finally {
  const destination = path.join(root, 'reports', `C7-agent-evaluation-${stamp}.json`);
  await writeFile(destination, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ report: destination, status: report.status, lanes: report.lanes.length, checks: report.checks.length, runtimeChecks: report.runtimeChecks.length, error: report.error?.message }));
}
