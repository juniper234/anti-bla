import { mkdir, open, readFile, writeFile, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Controlled, implementation-informed fixture replay only. No target execution,
// imports or upstream tests/challenge. REA performs its pinned static task.
const root = fileURLToPath(new URL('..', import.meta.url));
const loaderControls = process.argv.includes('--loader-controls');
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const runRoot = path.join(root, 'scratch/sidecars', `qualification-${stamp}`);
const workspace = path.join(runRoot, 'views');
const reportPrefix = path.join(root, 'reports', `C8-sidecar-${loaderControls ? 'loader-' : ''}qualification-${stamp}`);
const runtime = path.join(root, '.runtime/node-v24.22.1-win-x64/node.exe');
const wrapper = path.join(root, 'research/rea/scripts/rea.mjs');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const expected = '/api/invoice/status';
await mkdir(workspace, {recursive: true});
const report = { schema: 'anti-bla.sidecar-qualification/1', startedAt: new Date().toISOString(),
  sourceOrigin: loaderControls ? 'Own inert JS/JSX/TS/TSX syntax controls; TS/TSX reproduce independent C8-S1 review fixtures. No target execution or upstream BLA tests/challenge.' :
    'Existing independently authored C3 controlled fixtures; implementation-source-informed, no upstream BLA tests/challenge.',
  workspace, commandLog: [], runs: [], controls: [], hashes: [], passed: false,
  task: { entryExport: 'register', argumentIndex: 0, expected,
    criterion: 'Exactly one semantic call site in register, hash-bound to the derivative, argument index0 equals the expected path, and linked application endpoint mechanism equals call:<register parameter>.post at the same source range.' },
  fullEquivalence: 'UNKNOWN', dynamicExecution: 'NOT_RUN', resources: null,
  limitation: 'Selected static call-site tasks only. Earlier contained observations may be linked for byte-identical derivatives; no new runtime behavior or universal recovery claim.' };

async function run(executable, args, label, timeoutMs = 90000) {
  const prefix = `${reportPrefix}-${label}`;
  const stdoutPath = prefix + '.stdout.log', stderrPath = prefix + '.stderr.log';
  const stdout = await open(stdoutPath, 'wx'), stderr = await open(stderrPath, 'wx');
  const startedAt = new Date().toISOString(), started = performance.now();
  const child = spawn(executable, args, { cwd: root, windowsHide: true,
    stdio: ['ignore', stdout.fd, stderr.fd], env: { ...process.env,
      TEMP: path.join(root, 'scratch/providers/temp'), TMP: path.join(root, 'scratch/providers/temp') } });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
  const outcome = await new Promise(resolve => { child.once('error', error => resolve({ exitCode: null, error: error.message }));
    child.once('exit', (exitCode, signal) => resolve({ exitCode, signal })); });
  clearTimeout(timer); await stdout.close(); await stderr.close();
  const record = { executable, args, startedAt, finishedAt: new Date().toISOString(), wallMs: performance.now() - started,
    ...outcome, timedOut, stdoutPath, stderrPath, stdoutBytes: (await stat(stdoutPath)).size,
    stderrBytes: (await stat(stderrPath)).size, stdoutSha256: sha(await readFile(stdoutPath)), stderrSha256: sha(await readFile(stderrPath)),
    childPeakMemoryBytes: null };
  report.commandLog.push(record); return record;
}
async function json(file) { try { return JSON.parse(await readFile(file, 'utf8')); } catch { return null; } }
function sameRange(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function sourceRange(source, range) {
  if (!range || !Number.isInteger(range.start?.line) || !Number.isInteger(range.end?.line)) return null;
  const lines = source.split('\n');
  if (range.start.line < 1 || range.end.line > lines.length || range.start.line > range.end.line) return null;
  const selected = lines.slice(range.start.line - 1, range.end.line);
  if (selected.length === 1) return selected[0].slice(range.start.column, range.end.column);
  selected[0] = selected[0].slice(range.start.column); selected[selected.length - 1] = selected.at(-1).slice(0, range.end.column);
  return selected.join('\n');
}
function recover(raw, bytes, modulePath) {
  const graph = raw?.normalized_result?.semantic_graph, application = raw?.normalized_result?.graph;
  const source = bytes.toString('utf8'), hash = sha(bytes);
  const functions = (graph?.nodes ?? []).filter(node => node.kind === 'function' && node.label === 'register' &&
    node.identity?.artifact_sha256 === hash && node.identity.module_path === modulePath);
  const matches = [];
  for (const fn of functions) {
    const fnText = sourceRange(source, fn.identity.source_range);
    // Fixed predicate over the owned fixture. The callee must be the selected
    // function's parameter.post; arbitrary console.log literal matches fail.
    const parameter = fnText?.match(/^function register\(([A-Za-z_$][A-Za-z0-9_$]*)(?:: any)?\)/)?.[1];
    if (!parameter) continue;
    for (const call of graph.nodes.filter(node => node.kind === 'call-site' && node.function_node_id === fn.node_id &&
      node.identity?.artifact_sha256 === hash && node.identity.module_path === modulePath)) {
      const argument = call.properties?.arguments?.find(arg => arg.index === 0 && arg.value === expected);
      const callText = sourceRange(source, call.identity.source_range);
      if (!argument || !callText?.startsWith(`${parameter}.post(`)) continue;
      const endpoint = (application?.nodes ?? []).flatMap(node => (call.application_node_ids ?? []).includes(node.node_id) &&
        node.identity?.artifact_sha256 === hash ? node.observations ?? [] : []).find(observation =>
        observation.properties?.mechanism === `call:${parameter}.post` && observation.properties?.value === expected &&
        observation.evidence?.artifact?.sha256 === hash &&
        sameRange({start:observation.evidence?.location?.value?.start,end:observation.evidence?.location?.value?.end}, call.identity.source_range));
      if (endpoint) matches.push({ functionNodeId: fn.node_id, callNodeId: call.node_id, modulePath, artifactSha256: hash,
        range: call.identity.source_range, callee: `${parameter}.post`, argument, endpointObservationId: endpoint.observation_id });
    }
  }
  return { taskRecovered: matches.length === 1, matches,
    rawStatus: raw?.status ?? raw?.code ?? null, semanticCoverage: graph?.coverage ?? null,
    statistics: raw?.normalized_result?.statistics ?? null, limitations: raw?.normalized_result?.limitations ?? null };
}
try {
  const prior = loaderControls ? null : await json(path.join(root, 'reports/C3-qualification.json'));
  if (!loaderControls && (prior?.schema !== 'anti-bla.javascript-qualification/1' || !prior.finishedAt)) throw new Error('Completed C3 record required');
  const selected = prior?.runs.filter(row => row.intensity === 'stealth') ?? [];
  if (!loaderControls && (selected.length !== 3 || new Set(selected.map(row => row.seed)).size !== 3)) throw new Error('Three independently seeded fixtures required');
  for (const file of ['scripts/qualify-sidecars.mjs', 'src/sidecars.ts', 'dist/sidecars.js', 'dist/analysis-worker.js', 'dist/service.js',
    'dist/server.js', 'dist/cli.js', 'dist/javascript.js', 'research/rea/scripts/rea.mjs', 'research/rea/dist/cli.js',
    '.runtime/providers/environment.ps1', 'reports/C3-qualification.json']) {
    report.hashes.push({ path: file, sha256: sha(await readFile(path.join(root, file))) });
  }
  report.providerEnvironment = Object.fromEntries(['JAVA_HOME', 'GHIDRA_INSTALL_DIR', 'REA_WABT_BIN_DIRECTORY', 'REA_JADX_MCP_JAR',
    'REA_ILSPY_CMD_PATH', 'DOTNET_ROOT', 'TEMP', 'TMP'].map(name => [name, process.env[name] ?? null]));
  const nodeVersion = await run(runtime, ['--version'], 'runtime');
  if ((await readFile(nodeVersion.stdoutPath, 'utf8')).trim() !== 'v24.22.1') throw new Error('Unexpected isolated runtime');
  const revision = await run('git', ['-C', path.join(root, 'research/rea'), 'rev-parse', 'HEAD'], 'rea-pin');
  if ((await readFile(revision.stdoutPath, 'utf8')).trim() !== '317bf3fe235e655b2d752d3be261cc0da7d00f2b') throw new Error('Wrong source REA pin');
  report.reaPin = '317bf3fe235e655b2d752d3be261cc0da7d00f2b';
  const reaVersion = await run(runtime, [wrapper, '--version'], 'rea-version');
  report.reaVersionOutput = (await readFile(reaVersion.stdoutPath, 'utf8')).trim();
  if (loaderControls) for (const [loader, filename, source] of [
    ['js','inspection.mjs','export function register(router){router.post("/api/invoice/status",()=>{});}'],
    ['jsx','inspection.jsx','export function register(router){router.post("/api/invoice/status",()=> <span/>);}'],
    ['ts','inspection.ts','export function register(router: any): void {router.post("/api/invoice/status",()=>{});}'],
    ['tsx','inspection.tsx','export function register(router: any): void {router.post("/api/invoice/status",()=> <span/>);}'],
  ]) {
    const directory = path.join(runRoot, loader); await mkdir(directory);
    const originalPath = path.join(directory, 'original.artifact'); await writeFile(originalPath, source, {flag:'wx'});
    const row = {loader, expectedFilename:filename, originalPath, originalSha256:sha(source)}; report.runs.push(row);
    row.prepareCommand = await run(runtime, [path.join(root,'dist/cli.js'),'prepare-javascript-view',originalPath,
      '--root',directory,'--workspace',workspace,'--loader',loader], `${loader}-prepare`);
    row.prepareResult = await json(row.prepareCommand.stdoutPath);
    if (row.prepareCommand.exitCode !== 0 || row.prepareResult?.status !== 'ok') {row.status='UNKNOWN'; continue;}
    const locator = row.prepareResult.sidecar;
    const bytes = await readFile(locator.viewPath), evidence = await readFile(locator.evidencePath);
    row.evidence = JSON.parse(evidence); row.exportedSha256 = sha(bytes);
    row.syntaxBytesUnchanged = bytes.toString('utf8') === source;
    row.filenameMatches = path.basename(locator.viewPath) === filename && row.evidence.derivative.filename === filename;
    row.proofHashesMatch = locator.derivativeSha256 === sha(bytes) && locator.evidenceSha256 === sha(evidence);
    row.originalUnchanged = sha(await readFile(originalPath)) === row.originalSha256;
    row.reaCommand = await run(runtime,[wrapper,'analyze-javascript-application',locator.viewDirectory,'--format','json'],`${loader}-rea`);
    row.recovery = recover(await json(row.reaCommand.stdoutPath),bytes,path.basename(locator.viewPath));
    row.status = row.syntaxBytesUnchanged && row.filenameMatches && row.proofHashesMatch && row.originalUnchanged &&
      row.reaCommand.exitCode === 0 && row.recovery.statistics?.parse_failures === 0 && row.recovery.statistics?.visited_ast_nodes > 0 &&
      row.recovery.taskRecovered ? 'RECOVERED' : 'UNKNOWN';
    console.log(JSON.stringify({loader,status:row.status,filename:path.basename(locator.viewPath),parseFailures:row.recovery.statistics?.parse_failures,
      astNodes:row.recovery.statistics?.visited_ast_nodes,taskRecovered:row.recovery.taskRecovered}));
  }
  for (const [index, priorRow] of selected.entries()) {
    const originalPath = path.join(priorRow.protectedRea.command.args[2], 'index.mjs');
    const priorViewPath = path.join(priorRow.viewRea.command.args[2], 'index.mjs');
    const original = await readFile(originalPath), priorView = await readFile(priorViewPath);
    if (sha(original) !== priorRow.protectedSha256 || sha(priorView) !== priorRow.derivativeSha256) throw new Error('Existing fixture identity changed');
    const row = { seed: priorRow.seed, intensity: priorRow.intensity, originalPath, originalSha256: sha(original),
      expectedDerivativeSha256: priorRow.derivativeSha256, priorViewPath };
    report.runs.push(row);
    row.prepareCommand = await run(runtime, [path.join(root, 'dist/cli.js'), 'prepare-javascript-view', originalPath,
      '--root', path.dirname(originalPath), '--workspace', workspace, '--assume-standard-intrinsics'], `case${index + 1}-prepare`);
    row.prepareResult = await json(row.prepareCommand.stdoutPath);
    if (row.prepareCommand.exitCode !== 0 || row.prepareResult?.status !== 'ok') { row.status = 'UNKNOWN'; continue; }
    const locator = row.prepareResult.sidecar;
    const derivative = await readFile(locator.viewPath), evidence = await readFile(locator.evidencePath);
    row.exportedSha256 = sha(derivative); row.derivativeBytes = derivative.length;
    row.exactPriorBytes = derivative.equals(priorView); row.hashMatchesRecorded = sha(derivative) === priorRow.derivativeSha256;
    row.proofHashesMatch = locator.derivativeSha256 === sha(derivative) && locator.evidenceSha256 === sha(evidence);
    row.evidence = JSON.parse(evidence);
    row.reaCommand = await run(runtime, [wrapper, 'analyze-javascript-application', locator.viewDirectory, '--format', 'json'], `case${index + 1}-rea`);
    row.recovery = recover(await json(row.reaCommand.stdoutPath), derivative, 'inspection.mjs');
    const priorViewRaw = await json(priorRow.viewRea.command.stdoutPath);
    row.priorRecoveryRechecked = recover(priorViewRaw, priorView, 'index.mjs');
    row.priorReaRawUnchanged = sha(await readFile(priorRow.viewRea.command.stdoutPath)) === priorRow.viewRea.rawResultSha256;
    row.originalAfterSha256 = sha(await readFile(originalPath)); row.originalUnchanged = row.originalAfterSha256 === row.originalSha256;
    row.previousContainedObservation = { path: priorRow.viewDynamic.execute?.stdoutPath ?? null,
      status: priorRow.viewDynamic.status, checks: priorRow.viewDynamic.observation?.checks ?? null,
      attribution: 'Previous C3 run, byte-identical derivative; not newly executed by this exporter.' };
    row.status = row.exactPriorBytes && row.hashMatchesRecorded && row.proofHashesMatch && row.originalUnchanged &&
      row.priorReaRawUnchanged && row.priorRecoveryRechecked.taskRecovered && row.reaCommand.exitCode === 0 && row.recovery.taskRecovered ? 'RECOVERED' : 'UNKNOWN';
    console.log(JSON.stringify({case:index + 1,status:row.status,sourceSha256:row.originalSha256,derivativeSha256:row.exportedSha256}));
  }
  // Actual pinned REA negative controls, not a text-only string-presence oracle.
  for (const [name, filename, source] of [
    ['wrong-callee', 'inspection.mjs', 'export function register(router){console.log("/api/invoice/status");}'],
    ['wrong-index', 'inspection.mjs', 'export function register(router){router.post("other","/api/invoice/status");}'],
    ['normal-control', 'inspection.mjs', 'export function register(router){router.post("/api/invoice/status",()=>{});}'],
    ...(loaderControls ? [
      ['wrong-callee-ts', 'inspection.ts', 'export function register(router: any): void {console.log("/api/invoice/status");}'],
      ['wrong-index-tsx', 'inspection.tsx', 'export function register(router: any): void {router.post("other","/api/invoice/status",()=> <span/>);}'],
    ] : []),
  ]) {
    const directory = path.join(runRoot, name); await mkdir(directory);
    const bytes = Buffer.from(source); await writeFile(path.join(directory, filename), bytes, {flag:'wx'});
    const command = await run(runtime, [wrapper, 'analyze-javascript-application', directory, '--format', 'json'], name);
    const recovery = recover(await json(command.stdoutPath), bytes, filename);
    report.controls.push({name,sha256:sha(bytes),command,recovery,passed:command.exitCode === 0 &&
      recovery.statistics?.parse_failures === 0 && recovery.statistics?.visited_ast_nodes > 0 && recovery.taskRecovered === (name === 'normal-control')});
  }
  report.passed = report.runs.length === (loaderControls ? 4 : 3) && report.runs.every(row => row.status === 'RECOVERED') && report.controls.every(control => control.passed);
} catch (error) { report.failure = {message:error.message}; }
report.finishedAt = new Date().toISOString();
await writeFile(reportPrefix + '.json', JSON.stringify(report, null, 2) + '\n', {flag:'wx'});
console.log(JSON.stringify({passed:report.passed,runs:report.runs.map(row=>row.status),controls:report.controls.map(row=>({name:row.name,passed:row.passed})),reportPath:reportPrefix+'.json'}));
if (!report.passed) process.exitCode = 1;
