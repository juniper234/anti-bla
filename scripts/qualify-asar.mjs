import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = fileURLToPath(import.meta.url);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const pins = { bla: 'b2d643600774d62e562081129e55b13b0d9e8a80', rea: '317bf3fe235e655b2d752d3be261cc0da7d00f2b' };
const kinds = ['clean', 'amplifier', 'benign-control', 'protector', 'corrupt-pickle'];
const MiB = 1024 * 1024;
const imported = relative => import(pathToFileURL(path.join(root, relative)).href);
const errorRecord = error => ({ name: error?.name ?? null, code: error?.code ?? null, reason: error?.reason ?? null,
  message: String(error?.message ?? error), cause: error?.cause ? errorRecord(error.cause) : null });

// Authored independently of either ASAR implementation, including its framing.
function independentArchive(files) {
  const header = { files: Object.create(null) }; const payloads = []; let offset = 0;
  for (const [name, content] of files) {
    header.files[name] = { offset: String(offset), size: content.length };
    payloads.push(content); offset += content.length;
  }
  const json = Buffer.from(JSON.stringify(header));
  const prefix = Buffer.alloc(16 + Math.ceil(json.length / 4) * 4);
  prefix.writeUInt32LE(4, 0); prefix.writeUInt32LE(prefix.length - 8, 4);
  prefix.writeUInt32LE(prefix.length - 12, 8); prefix.writeUInt32LE(json.length, 12); json.copy(prefix, 16);
  return Buffer.concat([prefix, ...payloads]);
}
function referenceEntry(bytes, name) {
  const header = JSON.parse(bytes.subarray(16, 16 + bytes.readUInt32LE(12)).toString('utf8'));
  const node = header.files[name];
  const start = 8 + bytes.readUInt32LE(4) + Number(node.offset);
  return { start, bytes: bytes.subarray(start, start + node.size) };
}
function compactInspection(result) {
  const rendered = JSON.stringify(result);
  return { status: result.status, reason: result.reason ?? null, archive: result.archive ?? null,
    header: result.header ?? null, totalEntries: result.totalEntries ?? null, counts: result.counts ?? null,
    returned_entries: result.entries?.length ?? null, output_json_bytes: Buffer.byteLength(rendered),
    first_paths: result.entries?.slice(0, 3).map(entry => entry.path) ?? [],
    behavioral_equivalence: result.behavioralEquivalence, limitations: result.limitations };
}
async function realRea(pathname, references, admission, label) {
  const start = performance.now(); let reader; const result = { label, admission: { maximumBytes: admission.maximumBytes, source: admission.source },
    status: 'UNKNOWN', entry_count: null, entries: [], error: null, cleanup_error: null, wall_ms: null };
  try {
    const { AsarArtifactReader } = await imported('research/rea/dist/artifacts/AsarArtifactReader.js');
    reader = new AsarArtifactReader(pathname, { headerAdmission: admission });
    let count = 0; const selected = [];
    for await (const entry of reader.entries(AbortSignal.timeout(20_000))) {
      count++; if (references.has(entry.path)) selected.push(entry);
    }
    result.entry_count = count;
    for (const entry of selected) {
      const chunks = []; let length = 0;
      const stream = await reader.open(entry, AbortSignal.timeout(20_000));
      for await (const chunk of stream) {
        length += chunk.length;
        if (length > 8 * MiB) { stream.destroy(); throw new Error('Controlled fixture entry exceeded qualification 8 MiB read cap'); }
        chunks.push(chunk);
      }
      const bytes = Buffer.concat(chunks), reference = references.get(entry.path);
      result.entries.push({ path: entry.path, byte_length: bytes.length, sha256: sha(bytes),
        expected_packed_sha256: sha(reference), matches_original_archive_packed_bytes: bytes.equals(reference) });
    }
    result.status = result.entries.length === references.size && result.entries.every(entry => entry.matches_original_archive_packed_bytes)
      ? 'PACKED_BYTES_RECOVERED' : 'UNKNOWN';
  } catch (error) { result.error = errorRecord(error); }
  finally {
    if (reader) try { await reader.close(); } catch (error) { result.cleanup_error = errorRecord(error); result.status = 'UNKNOWN'; }
    result.wall_ms = performance.now() - start;
  }
  return result;
}

async function oneCase(kind, seed) {
  const began = performance.now();
  const { inspectAsar, readAsarEntry } = await imported('dist/asar.js');
  const { packAsarBuffer } = await imported('research/bla/dist/shields/formats/asar.js');
  const { SeededPrng } = await imported('research/bla/dist/core/prng.js');
  const { planAsarHeaderAmplification } = await imported('research/bla/dist/shields/exhaustion/asar-header-amplifier.js');
  const base = path.join(root, 'scratch', 'asar'); await mkdir(base, { recursive: true });
  const directory = await mkdtemp(path.join(base, `${kind}-${sha(Buffer.from(seed)).slice(0, 8)}-`));
  const temp = path.join(directory, 'temp'); await mkdir(temp);
  process.env.TEMP = temp; process.env.TMP = temp; // Per-process only; REA owns snapshots beneath this root.
  const input = path.join(directory, 'controlled-clean.asar'), output = path.join(directory, 'controlled.asar');
  const manifest = Buffer.from(JSON.stringify({ name: 'anti-bla-c4-controlled', version: '1.0.0', main: 'main.js', fixtureSeed: seed }));
  const main = Buffer.from(`'use strict';\nmodule.exports = Object.freeze({ answer: 42, fixture: ${JSON.stringify(seed)} });\n`);
  const originals = new Map([['package.json', manifest], ['main.js', main]]);
  const clean = independentArchive(originals);
  await writeFile(input, clean, { flag: 'wx' });
  const result = { kind, seed, fixture_origin: 'independently authored literal package/main and Pickle framing', input_sha256: sha(clean),
    input_bytes: clean.length, emitter: null, output_sha256: null, output_bytes: null, header_bytes: null,
    anti_bla: null, rea: [], settings: null, behavioral_equivalence: 'UNKNOWN', target_execution: false,
    expected: { packed_manifest_original: true, packed_main_original: kind !== 'protector', default_rea_admission: ['clean', 'corrupt-pickle'].includes(kind) ? (kind === 'clean' ? 'admit' : 'reject') : 'reject',
      anti_bla_structure: kind === 'corrupt-pickle' ? 'error' : 'ok' },
    expectation_met: false, failures: [], cleanup: null };
  try {
    let bytes = clean;
    if (kind === 'amplifier' || kind === 'benign-control') {
      const started = performance.now();
      const plan = planAsarHeaderAmplification(new SeededPrng(seed), 'bankrupt');
      const files = [...originals].map(([relativePath, content]) => ({ relativePath, content }));
      let extras = plan.files;
      if (kind === 'benign-control') {
        // A controlled corpus of long catalog identifiers, with equal path/body
        // lengths. These are ordinary data assets, not a decoy classification.
        extras = plan.files.map((entry, index) => {
          const name = `catalog/tables/report-row-${'b'.repeat(3)}-${'c'.repeat(4096)}_${index}.json`;
          if (Buffer.byteLength(name) !== Buffer.byteLength(entry.relativePath)) throw new Error('Benign path length parity failed');
          return { relativePath: name, content: Buffer.alloc(entry.content.length, 0x20) };
        });
      }
      bytes = packAsarBuffer([...files, ...extras]);
      const amplifierReference = kind === 'benign-control' ? packAsarBuffer([...files, ...plan.files]) : bytes;
      result.emitter = { api: kind === 'amplifier'
        ? 'planAsarHeaderAmplification(new SeededPrng(seed), "bankrupt"); packAsarBuffer([...literalFiles, ...plan.files])'
        : 'independently named catalog assets with same measured path/body lengths; pinned packAsarBuffer',
        intensity: 'bankrupt', generated_entry_count: extras.length, wall_ms: performance.now() - started,
        amplifier_reference_sha256: sha(amplifierReference), amplifier_reference_header_bytes: amplifierReference.readUInt32LE(4),
        header_length_equal_to_actual_amplifier: bytes.readUInt32LE(4) === amplifierReference.readUInt32LE(4) };
    } else if (kind === 'protector') {
      const { protectTarget } = await imported('research/bla/dist/engine/protector.js');
      const started = performance.now();
      const protection = protectTarget({ inputPath: input, outputPath: output, intensity: 'bankrupt', seed });
      bytes = await readFile(output);
      result.emitter = { api: 'protectTarget({inputPath, outputPath, intensity:"bankrupt", seed})', intensity: 'bankrupt', wall_ms: performance.now() - started,
        actual_result: { success: protection.success ?? null, format: protection.format ?? null,
          binarySectionsPatched: protection.binarySectionsPatched ?? null } };
    } else if (kind === 'corrupt-pickle') {
      bytes = Buffer.from(clean); bytes.writeUInt32LE(bytes.readUInt32LE(8) + 4, 8);
      result.emitter = { api: 'independent clean fixture; corrupt inner payload length by +4', mutation_byte_offset: 8 };
    } else result.emitter = { api: 'independentArchive(literalFiles); no upstream packer' };
    if (kind !== 'protector') await writeFile(output, bytes, { flag: 'wx' });
    result.output_sha256 = sha(bytes); result.output_bytes = bytes.length; result.header_bytes = bytes.readUInt32LE(4);
    const inspected = inspectAsar(bytes);
    result.anti_bla = { inspection: compactInspection(inspected), entries: [], wall_ms: null };
    const adapterStart = performance.now();
    const references = new Map();
    if (kind !== 'corrupt-pickle') {
      for (const [name, original] of originals) {
        const packed = referenceEntry(bytes, name); references.set(name, packed.bytes);
        const observed = readAsarEntry(bytes, { path: name, length: 4096 });
        const view = observed.view ? Buffer.from(observed.view.base64, 'base64') : null;
        result.anti_bla.entries.push({ path: name, status: observed.status, reason: observed.reason ?? null,
          original_sha256: sha(original), packed_sha256: sha(packed.bytes), original_length: original.length, packed_length: packed.bytes.length,
          packed_bytes_equal_original: packed.bytes.equals(original), observed_view: observed.view ?? null,
          matches_original_archive_byte_range: !!view && observed.view.archiveOffset === packed.start && view.equals(packed.bytes.subarray(0, 4096)),
          entire_original_recovered: !!view && view.equals(original) });
      }
    }
    result.anti_bla.wall_ms = performance.now() - adapterStart;
    try {
      const { resolveAsarHeaderAdmission } = await imported('research/rea/dist/artifacts/AsarHeader.js');
      const { AnalysisSettings } = await imported('research/rea/dist/application/AnalysisSettings.js');
      const { runtimeAsarHeaderAdmission } = await imported('research/rea/dist/config/runtimeAnalysisSettings.js');
      const settings = new AnalysisSettings({});
      const update = settings.update({ changes: [{ setting: 'asar.max_header_bytes', action: 'set', value: 256 * MiB }] });
      const overMaximum = settings.update({ changes: [{ setting: 'asar.max_header_bytes', action: 'set', value: 256 * MiB + 1 }] });
      result.settings = { environment_setting: 'REA_ASAR_MAX_HEADER_BYTES', runtime_setting: 'asar.max_header_bytes',
        inspected: settings.inspect({ settings: ['asar.max_header_bytes'] }), runtime_update: update,
        rejects_above_256_mib: !overMaximum.ok };
      const admissions = [
        ['default', resolveAsarHeaderAdmission({})],
        ['environment-32MiB', resolveAsarHeaderAdmission({ REA_ASAR_MAX_HEADER_BYTES: String(32 * MiB) })],
        ['environment-256MiB', resolveAsarHeaderAdmission({ REA_ASAR_MAX_HEADER_BYTES: String(256 * MiB) })],
        ['runtime-256MiB', runtimeAsarHeaderAdmission({}, settings.read)],
      ];
      for (const [label, admission] of admissions) result.rea.push(await realRea(output, references, admission, label));
    } catch (error) { result.failures.push({ stage: 'REA prerequisite/configuration', error: errorRecord(error) }); }
    const adapterOk = inspected.status === result.expected.anti_bla_structure && (kind === 'corrupt-pickle'
      || result.anti_bla.entries.every(entry => entry.status === 'ok' && entry.matches_original_archive_byte_range && entry.packed_bytes_equal_original === (entry.path === 'package.json' || kind !== 'protector')));
    const defaultResult = result.rea.find(row => row.label === 'default');
    const reaOk = kind === 'corrupt-pickle'
      ? result.rea.length === 4 && result.rea.every(row => row.error?.reason === 'format')
      : result.rea.length === 4 && result.rea.filter(row => row.label !== 'default').every(row => row.status === 'PACKED_BYTES_RECOVERED')
        && (kind === 'clean' ? defaultResult?.status === 'PACKED_BYTES_RECOVERED' : defaultResult?.error?.reason === 'limit');
    result.expectation_met = adapterOk && reaOk && result.failures.length === 0
      && (kind !== 'benign-control' || result.emitter.header_length_equal_to_actual_amplifier);
    if (!adapterOk) result.failures.push({ stage: 'adapter expected behavior', observed: inspected.status });
    if (!reaOk) result.failures.push({ stage: 'real REA expected admission/packed-byte recovery', observed: result.rea.map(row => ({ label: row.label, status: row.status, reason: row.error?.reason ?? null })) });
  } catch (error) { result.failures.push({ stage: 'case generation/qualification', error: errorRecord(error) }); }
  finally {
    result.resources = { process_memory_usage: process.memoryUsage(), process_resource_usage: process.resourceUsage(),
      measured_child_peak_rss_kib: process.resourceUsage().maxRSS, wall_ms: performance.now() - began, cpu_limits: null };
    try { await rm(directory, { recursive: true, force: true }); result.cleanup = 'own-controlled-directory-removed'; }
    catch (error) { result.cleanup = errorRecord(error); result.expectation_met = false; }
  }
  console.log(`C4RESULT ${JSON.stringify(result)}`);
  process.exitCode = result.expectation_met ? 0 : 1;
}

async function qualify() {
  const startedAt = new Date().toISOString(), started = performance.now();
  const supplied = process.argv.find(arg => arg.startsWith('--seeds='));
  const seeds = supplied ? supplied.slice(8).split(',') : Array.from({ length: 3 }, () => `c4-${randomBytes(16).toString('hex')}`);
  if (seeds.length !== 3 || new Set(seeds).size !== 3 || seeds.some(seed => !/^[a-zA-Z0-9_-]{1,96}$/u.test(seed))) throw new Error('Exactly three distinct bounded alphanumeric seeds required');
  const runId = startedAt.replace(/[^0-9]/gu, '');
  const report = { schema: 'anti-bla.C4-asar-qualification/1', started_at: startedAt, runtime: { executable: process.execPath, version: process.version, platform: process.platform, architecture: process.arch },
    command: [process.execPath, ...process.argv.slice(1)], pins, observed_pins: {}, seeds, controlled_target_execution: false,
    baseline: 'Real pinned source-built REA AsarArtifactReader; inventory and packed entry streams. This is a provider-level static recovery task, not complete REA analysis or executable equivalence.',
    limitations: ['Source-visible white-box experiment; no BLA tests or challenge answers read.',
      'Only controlled ASAR fixtures; no artifact, JavaScript main, or target-supplied command is executed.',
      'Full protector changes main.js: original JavaScript recovery and behavioral equivalence remain UNKNOWN.',
      'REA configured header admission success removes that obstruction only; packed-byte comparisons are reported separately.',
      'ASAR integrity declarations, external Electron signatures and fuse hardening are not bypassed or verified.'], cases: [], failures: [], completed_at: null, wall_ms: null };
  for (const name of ['bla', 'rea']) {
    const command = spawnSync('git', ['-C', path.join(root, 'research', name), 'rev-parse', 'HEAD'], { encoding: 'utf8', windowsHide: true });
    report.observed_pins[name] = { command: ['git', '-C', `research/${name}`, 'rev-parse', 'HEAD'], exit_code: command.status,
      commit: command.stdout.trim(), stderr: command.stderr };
    if (command.status !== 0 || command.stdout.trim() !== pins[name]) report.failures.push({ stage: 'pin verification', upstream: name });
  }
  await mkdir(path.join(root, 'reports'), { recursive: true });
  for (const seed of seeds) for (const kind of kinds) {
    const args = [script, '--case', kind, seed], start = performance.now();
    const child = spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', windowsHide: true,
      timeout: 60_000, maxBuffer: 2 * MiB, env: { ...process.env } });
    const raw = `COMMAND ${JSON.stringify([process.execPath, ...args])}\nEXIT ${child.status}\nSIGNAL ${child.signal}\nSTDOUT\n${child.stdout ?? ''}\nSTDERR\n${child.stderr ?? ''}\nERROR ${child.error ? JSON.stringify(errorRecord(child.error)) : 'null'}\n`;
    const filename = `C4-${runId}-${kind}-${sha(Buffer.from(seed)).slice(0, 8)}.log`;
    await writeFile(path.join(root, 'reports', filename), raw);
    const line = child.stdout?.split(/\r?\n/u).findLast(value => value.startsWith('C4RESULT '));
    let result = null; if (line) try { result = JSON.parse(line.slice(9)); } catch { /* Preserve raw failure. */ }
    report.cases.push({ command: [process.execPath, ...args], exit_code: child.status, signal: child.signal,
      wall_ms: performance.now() - start, raw_log: `reports/${filename}`, result,
      error: child.error ? errorRecord(child.error) : null });
    console.log(JSON.stringify({ kind, seed, exit_code: child.status, expectation_met: result?.expectation_met ?? false,
      adapter_status: result?.anti_bla?.inspection.status ?? null, failures: result?.failures ?? [] }));
  }
  report.completed_at = new Date().toISOString(); report.wall_ms = performance.now() - started;
  report.status = report.failures.length === 0 && report.cases.length === 15 && report.cases.every(row => row.exit_code === 0 && row.result?.expectation_met)
    ? 'STATIC_ASAR_TASK_QUALIFIED' : 'CONDITIONAL';
  const pathname = path.join(root, 'reports', `C4-qualification-${runId}.json`);
  await writeFile(pathname, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ report: pathname, status: report.status, cases: report.cases.length, wall_ms: report.wall_ms }));
  process.exitCode = report.status === 'STATIC_ASAR_TASK_QUALIFIED' ? 0 : 1;
}

if (process.argv[2] === '--case') {
  if (!kinds.includes(process.argv[3]) || !/^[a-zA-Z0-9_-]{1,96}$/u.test(process.argv[4] ?? '')) throw new Error('Invalid controlled case selector');
  await oneCase(process.argv[3], process.argv[4]);
} else await qualify();
