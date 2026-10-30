import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, writeFile, mkdir, open, readdir } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { getCurrentFuseWire } from '../.tools/frameworks/node_modules/@electron/fuses/dist/index.js';

// Only our parser runs in this mode. The input Electron executable is read as data.
if (process.argv[2] === '--official-reader') {
  try { console.log(JSON.stringify({ reader: '@electron/fuses getCurrentFuseWire', targetExecution: false, wire: await getCurrentFuseWire(process.argv[3]) })); }
  catch (e) { console.error(String(e)); process.exitCode = 1; }
} else await qualify();

async function qualify() {
  const root = process.cwd(), script = resolve(root, 'scripts/qualify-electron-views.mjs');
  const frozen = resolve(root, 'reports/C5-genuine-electron-2026-10-30T05-21-22-934Z.json');
  const frozenRaw = await readFile(frozen), original = JSON.parse(frozenRaw);
  const node = resolve(root, '.runtime/node-v24.22.1-win-x64/node.exe');
  const runId = new Date().toISOString().replace(/[:.]/g, '-'), scratch = resolve(root, 'scratch/electron-views', runId);
  await mkdir(scratch, { recursive: true });
  const reportPath = resolve(root, `reports/C5-electron-views-${runId}.json`);
  const sha = b => createHash('sha256').update(b).digest('hex');
  const offset = original.distribution.officialFuseCoordinates[0].fileOffset, length = 42;
  const limits = { maxInputBytes: 268435456, maxOutputBytes: 65536, timeoutMs: 5000, workerHeapMb: 128 };
  const cookie = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'ascii');
  const names = ['RunAsNode', 'EnableCookieEncryption', 'EnableNodeOptionsEnvironmentVariable', 'EnableNodeCliInspectArguments', 'EnableEmbeddedAsarIntegrityValidation', 'OnlyLoadAppFromAsar', 'LoadBrowserProcessSpecificV8Snapshot', 'GrantFileProtocolExtraPrivileges'];
  const report = {
    schema: 'anti-bla.electron-bounded-views/1', startedAt: new Date().toISOString(), invocation: [process.execPath, ...process.argv.slice(1)],
    status: 'UNKNOWN', audit_source: 'self', sourceInformed: true, targetExecution: false,
    frozen: { path: frozen, sha256: sha(frozenRaw), schema: original.schema },
    pins: original.sourcePins, coordinateOrigin: { path: frozen, field: 'distribution.officialFuseCoordinates[0].fileOffset', offset, length, boundary: 'original official distribution first and only sentinel; independently rescanned; same mapped coordinate in all three generated pairs' },
    limits: { defaultInputBytes: 67108864, explicitCoreAdmissionOverride: limits, rawViewHardMaximumBytes: 4096, nativeAdapterHardInputBytes: 67108864, nativeAdapterUnchanged: true },
    measurements: { wall: 'performance.now milliseconds', peakRssBytes: null, cpuSeconds: null, tokens: null, cost: null, warning: '128 MiB worker old-generation limit is not a total Buffer or RSS cap; no RSS estimate is made.' },
    sourceIdentities: [], commands: [], rows: [], controls: [], checks: [],
    claims: { selectedStaticFact: 'UNKNOWN', incrementalAntiRecoveryWin: false, enforcementBypass: false, executableEquivalence: 'UNKNOWN', runtimeAuthority: 'UNKNOWN', broadApplicationCodeRecovery: 'UNKNOWN', fullProtectedReaFuseReader: 'Retained original capacity refusal at 35 sentinels versus maximum32; not rerun or reclassified.' },
    limitations: ['Existing raw byte-view API qualification only; no product code, source/built distribution, limits, settings, or original artifact changes.', 'Coordinates come from source-informed frozen official-distribution evidence; this does not independently discover which of arbitrary decoys a runtime uses.', 'Official complete-file fuse reader already recovers the selected wire. No incremental Anti-BLA or enforcement bypass claim.', 'Raw view is an inspection range, not a native executable. No synthetic wrapper or arbitrary poison stripping, and no REA handoff of an unsupported raw42-byte container.'],
  };
  const t = performance.now();
  function check(name, value) { report.checks.push({ name, passed: value === true }); if (value !== true) throw Error(name); }
  async function identity(path) { const h = createHash('sha256'); let bytes = 0; for await (const b of createReadStream(path)) { h.update(b); bytes += b.length; } return { path, sha256: h.digest('hex'), bytes }; }
  async function range(path, at, count) { const f = await open(path, 'r'); try { const b = Buffer.alloc(count), r = await f.read(b, 0, count, at); return b.subarray(0, r.bytesRead); } finally { await f.close(); } }
  async function sentinels(path) { let tail = Buffer.alloc(0), consumed = 0; const positions = []; for await (const b of createReadStream(path, { highWaterMark: 262144 })) { const c = Buffer.concat([tail, b]), base = consumed - tail.length; for (let at = c.indexOf(cookie); at !== -1; at = c.indexOf(cookie, at + 1)) positions.push(base + at); consumed += b.length; tail = c.subarray(Math.max(0, c.length - cookie.length + 1)); } return positions; }
  async function command(id, args) {
    const startedAt = new Date().toISOString(), begin = performance.now(), out = [], err = []; let outputBytes = 0, stderrBytes = 0, timedOut = false, outputLimited = false, spawnError = null;
    const p = spawn(node, args, { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    p.stdout.on('data', b => { outputBytes += b.length; if (outputBytes <= 1048576) out.push(b); else { outputLimited = true; p.kill(); } });
    p.stderr.on('data', b => { stderrBytes += b.length; if (stderrBytes <= 1048576) err.push(b); else { outputLimited = true; p.kill(); } });
    const timer = setTimeout(() => { timedOut = true; p.kill(); }, 20000);
    const { code, signal } = await new Promise(done => { p.once('error', e => { spawnError = String(e); }); p.once('close', (code, signal) => done({ code, signal })); });
    clearTimeout(timer);
    const stdout = Buffer.concat(out), stderr = Buffer.concat(err), stdoutPath = join(scratch, `${id}.stdout.json`), stderrPath = join(scratch, `${id}.stderr.log`);
    await writeFile(stdoutPath, stdout); await writeFile(stderrPath, stderr); let parsed = null; try { parsed = JSON.parse(stdout); } catch {}
    const result = { id, command: [node, ...args], startedAt, completedAt: new Date().toISOString(), wallMs: performance.now() - begin, exitCode: code, signal, timedOut, outputLimited, spawnError, watchdogMs: 20000, stdoutPath, stderrPath, stdoutSha256: sha(stdout), stderrSha256: sha(stderr), stdoutBytes: stdout.length, stderrBytes: stderr.length, peakRssBytes: null, cpuSeconds: null, parsed };
    report.commands.push(result); return result;
  }
  function typedView(c, source, at, count, effective = limits) {
    try {
      const p = c.parsed, ev = p.evidence, v = p.view;
      if (c.exitCode !== 0 || c.timedOut !== false || c.outputLimited !== false || c.spawnError !== null || p.schema !== 'anti-bla.result/1' || p.operation !== 'read_artifact_view' || p.status !== 'ok' || p.behavioralEquivalence !== 'unknown') return null;
      if (p.artifact.sha256 !== source.sha256 || p.artifact.bytes !== source.bytes || p.provenance.trust !== 'untrusted-artifact' || p.provenance.originalSha256 !== source.sha256 || ev.schema !== 'anti-bla.evidence/1' || ev.operation !== p.operation || ev.input !== source.sha256 || ev.selection.offset !== at || ev.selection.length !== count || ev.analysisIdentity.implementationSha256 !== p.analysisIdentity.implementationSha256) return null;
      if (Object.keys(effective).some(k => ev.limits[k] !== effective[k]) || v.inspectionOnly !== true || v.range.offset !== at || v.range.length !== count || typeof v.base64 !== 'string') return null;
      if (sha(Buffer.from(JSON.stringify(ev))) !== p.evidenceId) return null;
      const b = Buffer.from(v.base64, 'base64'); return b.length === count && b.toString('base64') === v.base64 ? b : null;
    } catch { return null; }
  }
  function parseWire(b) {
    if (!Buffer.isBuffer(b) || b.length < 34 || !b.subarray(0, 32).equals(cookie)) return null;
    const version = b[32], declaredLength = b[33];
    if (version !== 1 || declaredLength !== 8 || b.length !== 34 + declaredLength) return null;
    const raw = [...b.subarray(34)], state = x => x === 48 ? 'disabled' : x === 49 ? 'enabled' : x === 114 ? 'removed' : null;
    if (raw.some(x => state(x) === null)) return null;
    return { cookieAscii: b.subarray(0, 32).toString('ascii'), cookieSha256: sha(b.subarray(0, 32)), wireVersion: version, declaredLength, rawBytes: raw, wireHex: b.subarray(34).toString('hex'), complete: true, fuses: raw.map((rawByte, index) => ({ index, name: names[index], rawByte, state: state(rawByte) })) };
  }
  const viewArgs = (source, at = offset, count = length, override = true) => [join(root, 'dist/cli.js'), 'read-artifact-view', source.path, '--root', dirname(source.path), '--offset', String(at), '--length', String(count), ...(override ? ['--max-input-bytes', String(limits.maxInputBytes)] : [])];
  try {
    check('frozen three independent seeds', original.runs.length === 3 && new Set(original.runs.map(x => x.seed)).size === 3);
    check('known genuine offset source bound', offset === 175184000 && original.distribution.officialFuseCoordinates.length === 1);
    const sourcePaths = [script, frozen, 'scripts/qualify-genuine-frameworks-verify-round1.mjs', 'src/contracts.ts', 'src/service.ts', 'src/analysis-worker.ts', 'src/artifacts.ts', 'src/native.ts', 'src/cli.ts', 'package.json', 'research/bla/src/shields/formats/electron-fuses.ts', 'research/rea/src/electron/ElectronFuseReader.ts', '.tools/frameworks/node_modules/@electron/fuses/dist/index.js', '.tools/frameworks/node_modules/@electron/fuses/dist/constants.js', '.tools/frameworks/node_modules/@electron/fuses/dist/config.js'];
    for (const p of (await readdir(join(root, 'dist'), { recursive: true })).filter(x => x.endsWith('.js')).sort()) sourcePaths.push(join('dist', p));
    for (const p of sourcePaths) report.sourceIdentities.push(await identity(resolve(root, p)));
    for (const pinned of original.sourceIdentities.filter(x => sourcePaths.map(p => resolve(root, p)).includes(x.path))) check(`frozen source identity ${pinned.path}`, (await identity(pinned.path)).sha256 === pinned.sha256);
    const defaults = await command('capabilities-default', [join(root, 'dist/cli.js'), 'capabilities', '--root', scratch]);
    check('actual defaults unchanged', defaults.exitCode === 0 && JSON.stringify(defaults.parsed.limits) === JSON.stringify({ ...limits, maxInputBytes: 67108864 }));
    const sources = [{ label: 'official-original', fixture: null, seed: null, identity: original.distribution.official }, ...original.runs.flatMap(r => [{ label: `fixture-${r.fixture}-clean`, fixture: r.fixture, seed: r.seed, identity: r.clean }, { label: `fixture-${r.fixture}-protected`, fixture: r.fixture, seed: r.seed, identity: r.protected }])];
    for (const s of sources) {
      const before = await identity(s.identity.path); check(`${s.label} frozen input`, before.sha256 === s.identity.sha256 && before.bytes === s.identity.bytes);
      const positions = await sentinels(before.path); check(`${s.label} independently searched first coordinate`, positions[0] === offset && positions.length === (s.label.endsWith('protected') ? 35 : 1));
      const baseline = await command(`${s.label}-default-view`, viewArgs(before, offset, length, false));
      check(`${s.label} default admission UNKNOWN`, baseline.exitCode === 3 && baseline.parsed.status === 'unknown' && baseline.parsed.reason.code === 'input_limit');
      const official = await command(`${s.label}-official-reader`, [script, '--official-reader', before.path]);
      check(`${s.label} official complete-file baseline succeeds`, official.exitCode === 0 && official.parsed.targetExecution === false && official.parsed.reader === '@electron/fuses getCurrentFuseWire' && official.parsed.wire.version === '1' && Object.keys(official.parsed.wire).length === 9);
      const view = await command(`${s.label}-override-view`, viewArgs(before)), bytes = typedView(view, before, offset, length), direct = await range(before.path, offset, length);
      check(`${s.label} exact typed source bytes`, bytes !== null && bytes.equals(direct));
      const parsed = parseWire(bytes); check(`${s.label} exact complete wire versus official reader`, parsed !== null && parsed.rawBytes.every((b, i) => official.parsed.wire[i] === b));
      const after = await identity(before.path); check(`${s.label} input unchanged`, after.sha256 === before.sha256 && after.bytes === before.bytes);
      report.rows.push({ label: s.label, fixture: s.fixture, seed: s.seed, source: before, sourceUnchanged: true, independentSentinelOffsets: positions, defaultViewCommand: baseline.id, explicitOverrideViewCommand: view.id, officialFullFileReaderCommand: official.id, sourceRange: { offset, length, endExclusive: offset + length, sha256: sha(bytes), base64: bytes.toString('base64') }, wire: parsed, officialWire: official.parsed.wire, defaultDeadlineAndHeap: true });
    }
    for (const r of original.runs) {
      const a = report.rows.find(x => x.label === `fixture-${r.fixture}-clean`), b = report.rows.find(x => x.label === `fixture-${r.fixture}-protected`), delta = a.wire.rawBytes.flatMap((byte, i) => byte !== b.wire.rawBytes[i] ? [{ index: i, fileOffset: offset + 34 + i, from: byte, to: b.wire.rawBytes[i] }] : []);
      check(`fixture${r.fixture} exact six changed fuse states`, delta.length === 6 && delta.every((x, i) => x.index === i)); b.sixChangedFuseBytes = delta;
      const native = await command(`fixture-${r.fixture}-native-override`, [join(root, 'dist/cli.js'), 'inspect-native', r.protected.path, '--root', dirname(r.protected.path), '--max-input-bytes', String(limits.maxInputBytes)]);
      check(`fixture${r.fixture} native adapter remains UNKNOWN`, native.exitCode === 3 && native.parsed.status === 'unknown' && native.parsed.reason === 'native input byte cap exceeded' && native.parsed.analysis.limits.inputBytes === 67108864);
    }
    const first = report.rows.find(x => x.label === 'fixture-1-protected'), source = first.source, good = report.commands.find(x => x.id === first.explicitOverrideViewCommand);
    for (const [label, at, count] of [['wrong-coordinate', offset + 1, length], ['empty-range', offset, 0]]) {
      const c = await command(`control-${label}`, viewArgs(source, at, count)), b = typedView(c, source, at, count);
      check(`${label} actual returned bytes cannot establish wire`, b !== null && parseWire(b) === null);
      report.controls.push({ label, command: c.id, source, sourceRange: { offset: at, length: count, sha256: sha(b) }, typedViewAccepted: true, wireRecognized: false });
    }
    for (const control of original.controls) {
      const before = await identity(control.artifact.path); check(`${control.label} frozen identity`, before.sha256 === control.artifact.sha256);
      const c = await command(`control-${control.label}`, viewArgs(before)), b = typedView(c, before, offset, length), p = parseWire(b);
      check(`${control.label} bound control`, b !== null && (control.label === 'malformed-wire' ? p === null && b[32] === 255 : p !== null && p.wireHex === report.rows.find(x => x.label === 'fixture-1-clean').wire.wireHex));
      report.controls.push({ label: control.label, command: c.id, source: before, sourceRange: { offset, length, sha256: sha(b) }, typedViewAccepted: true, wireRecognized: p !== null, wire: p });
    }
    for (const [label, mutate] of [['empty-typed-payload', c => { c.parsed.view.base64 = ''; }], ['wrong-returned-coordinate', c => { c.parsed.view.range.offset++; }], ['unbound-source-hash', c => { c.parsed.artifact.sha256 = '0'.repeat(64); }], ['wrong-evidence-selection', c => { c.parsed.evidence.selection.offset++; }], ['wrong-trust', c => { c.parsed.provenance.trust = 'trusted'; }], ['timeout', c => { c.timedOut = true; }], ['output-limited', c => { c.outputLimited = true; }], ['wrong-operation', c => { c.parsed.operation = 'inspect_native'; }]]) {
      const c = structuredClone(good); mutate(c); check(`negative typed control ${label}`, typedView(c, source, offset, length) === null); report.controls.push({ label, controlKind: 'negative predicate mutation, not a tool run', rejected: true });
    }
    check('wrong expected source identity rejected', typedView(good, { ...source, sha256: '0'.repeat(64) }, offset, length) === null);
    report.controls.push({ label: 'wrong-expected-source-identity', controlKind: 'source identity negative predicate mutation, not a tool run', rejected: true });
    for (const id of report.sourceIdentities) check(`unchanged source ${id.path}`, JSON.stringify(await identity(id.path)) === JSON.stringify(id));
    for (const row of report.rows) check(`final unchanged artifact ${row.label}`, JSON.stringify(await identity(row.source.path)) === JSON.stringify(row.source));
    for (const c of report.controls.filter(x => x.source)) check(`final unchanged control ${c.label}`, JSON.stringify(await identity(c.source.path)) === JSON.stringify(c.source));
    for (const c of report.commands) check(`raw process outputs bound ${c.id}`, sha(await readFile(c.stdoutPath)) === c.stdoutSha256 && sha(await readFile(c.stderrPath)) === c.stderrSha256 && c.timedOut === false && c.outputLimited === false && c.spawnError === null);
    report.status = 'SELF_VERIFIED_WITH_LIMITS'; report.claims.selectedStaticFact = 'All three frozen genuine Electron original/protected pairs: existing explicit256MiB-admission read-artifact-view returns exact42B genuine cookie/version/length/eight fuse bytes at original coordinate under default5s/128MiB-worker bounds. Six hardened bytes exactly match complete official-reader results; default core and native adapter refusals remain UNKNOWN.';
  } catch (e) { report.status = 'FAILED'; report.error = String(e); report.stack = e.stack; process.exitCode = 1; }
  report.completedAt = new Date().toISOString(); report.wallMs = performance.now() - t;
  await writeFile(reportPath, JSON.stringify(report, null, 2));
  const markdownPath = reportPath.replace(/\.json$/, '.md');
  await writeFile(markdownPath, `# Genuine Electron bounded byte-view qualification\n\n${report.status}; audit_source self. No independent review claim.\n\nFrozen input: ${frozen}\nSHA-256: ${report.frozen.sha256}\n\n${report.claims.selectedStaticFact}\n\nSelection: [${offset}, ${offset + length}), ${length} bytes (existing raw view hard maximum4096). Only --max-input-bytes268435456 is overridden. Deadline5000ms and worker old-generation128MiB are unchanged. Raw Buffer allocation and peak RSS are unmeasured; RSS null.\n\n${report.rows.map(x => `- ${x.label}: ${x.source.sha256}; rangeSHA256 ${x.sourceRange.sha256}; version${x.wire.wireVersion}, length${x.wire.declaredLength}, wireHex ${x.wire.wireHex}.`).join('\n')}\n\nOfficial full-file reader baseline already succeeds. Default core64MiB input admission and native adapter64MiB cap remain UNKNOWN. The source-informed mapped coordinate does not establish arbitrary runtime fuse authority, enforcement bypass, broad application-code recovery or executable equivalence. No target was executed, and no input bytes or product source/build/settings were changed. No unsupported raw-view REA wrapper was invented.\n\n${report.checks.length} checks; ${report.checks.filter(x => !x.passed).length} failures. Full process commands, exits, UTC, walltime, raw output hashes, immutable identities and controls are retained in the JSON.\n${report.error ? `\nFailure preserved: ${report.error}\n` : ''}`);
  console.log(JSON.stringify({ reportPath, markdownPath, status: report.status, checks: report.checks.length, failures: report.checks.filter(x => !x.passed), rows: report.rows.length, commands: report.commands.length }));
}
