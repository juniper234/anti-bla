import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

// Qualification index, not an additional recovery experiment. All references
// remain hash-bound; source coverage never becomes a behavioral success rate.
const root = path.resolve(import.meta.dirname, '..');
const stamp = new Date().toISOString().replaceAll(':', '-');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const identity = async relative => { const bytes = await readFile(path.join(root, relative)); return { path: relative, bytes: bytes.length, sha256: sha(bytes) }; };
const git = (repo, ...args) => execFileSync('git', ['-C', path.join(root, 'research', repo), ...args], { encoding: 'utf8' }).trim();
const inventory = JSON.parse(await readFile(path.join(root, 'docs/shield-inventory.json'), 'utf8'));
const expected = git('bla', 'ls-files', 'src/shields').split(/\r?\n/).sort();
assert.deepEqual(inventory.files.map(f => f.path).sort(), expected);
assert.equal(git('bla', 'rev-parse', 'HEAD'), inventory.bla.commit);
assert.equal(git('rea', 'rev-parse', 'HEAD'), inventory.rea.commit);
const refs = {
  source: ['docs/shield-inventory.json', 'reports/C0-source-assertions.json'],
  core: ['reports/C1-REVIEW.md'],
  js: ['reports/C3-qualification.json', 'reports/C3-controls.json', 'reports/C3-round1-revalidation.json', 'reports/C3-REVIEW-ROUND1.md'],
  asar: ['reports/C4-qualification-20261030015707496.json', 'reports/C4-REVIEW.md'],
  native: ['reports/C5-native.json', 'reports/C5-REVIEW-ROUND1.md'],
  data: ['reports/C6-data-summary.json', 'reports/C6-data-REVIEW-ROUND1.md'],
  containers: ['reports/C6-containers-2026-10-30T03-26-09-988Z.json', 'reports/C6-containers-REVIEW.md', 'reports/C6-containers-REVIEW-ROUND1.md'],
  bytecode: ['reports/C6-bytecode-audit-2026-10-30T04-35-33-876Z.json', 'reports/C6-bytecode-REVIEW.md', 'reports/C6-bytecode-REVIEW-ROUND1.md'],
  sidecars: ['reports/C8-sidecar-handoff.json', 'reports/C8-sidecar-REVIEW.md', 'reports/C8-sidecar-REVIEW-ROUND1.md', 'reports/C8-WHOLE-PROJECT-REVIEW.md'],
  frameworks: ['reports/C5-genuine-electron-2026-10-30T05-21-22-934Z.json', 'reports/C5-genuine-verification-round1-2026-10-30T05-32-40-201Z.json', 'reports/C5-genuine-REVIEW-ROUND1.md', 'reports/C5-genuine-flutter-2026-10-30T05-30-15-132Z.json', 'reports/C5-genuine-flutter-verification-round1-2026-10-30T05-36-24-494Z.json', 'reports/C5-genuine-FLUTTER-REVIEW.md', 'reports/C5-electron-views-2026-10-30T05-37-32-319Z.json', 'reports/C5-electron-views-REVIEW.md'],
  agents: ['reports/C7-agent-evaluation-2026-10-30T05-18-41.936Z.json', 'reports/C7-AGENT-SUMMARY.md', 'reports/C8-sidecar-REVIEW-ROUND1.md'],
};
const modules = [];
for (const file of inventory.files) {
  assert.equal(sha(await readFile(path.join(root, 'research/bla', file.path))), file.sha256, file.path);
  const name = path.basename(file.path);
  let group = 'js';
  let observation = 'Combined selected JS trials and source mapping; individual module causal effect not measured';
  let unresolved = 'Independent module ablation, agent damage/cost and general recovery UNKNOWN';
  if (name === 'index.ts' || name === 'rea-budget-matrix.ts') {
    group = 'source'; observation = 'Source dispatch/configuration mapped'; unresolved = 'No separate executable shield or independent recovery score is inferred';
  } else if (['asar.ts', 'asar-header-amplifier.ts'].includes(name)) {
    group = 'asar'; observation = 'Three-seed actual amplifier/header admission and exact packed member tasks independently checked';
    unresolved = 'Full application recovery and genuine integrity/fuse enforcement UNKNOWN';
  } else if (['wasm.ts', 'wasm-interface-exhaustion.ts', 'sqlite.ts', 'model.ts'].includes(name)) {
    group = 'data'; observation = 'Three-seed selected WASM/data tasks and independent parser/fix review; consult individual variant result';
    unresolved = name === 'model.ts' ? 'Protected original GGUF remains UNKNOWN; conditional structural candidate is not restored valid model/inference' : 'Whole-module/database semantics and general protected-input recovery UNKNOWN; SQLite baseline already works';
  } else if (['native.ts', 'headers.ts', 'go-flutter-exhaustion.ts', 'bun-standalone.ts', 'electron-fuses.ts'].includes(name)) {
    group = 'native'; observation = 'Genuine PE/Go/Rust/Bun selected facts and conservative layouts, with source-informed limits';
    unresolved = 'Broad ELF/Flutter business-function and enforcement tasks UNKNOWN; overwritten metadata not reconstructed; large Bun defaults refuse';
    if (name === 'electron-fuses.ts') { group = 'frameworks'; observation = 'Genuine Electron real-wire changes and resource/IPC coordinates3/3; existing explicit256MiB generic view returns exact known-range wire bytes'; unresolved = 'Official reader baseline already succeeds; native64MiB refusal, signatures and runtime enforcement remain UNKNOWN'; }
    if (name === 'go-flutter-exhaustion.ts') { group = 'frameworks'; observation = 'Genuine Flutter AOT snapshot metadata3/3, exact typed labels2/3, source-informed alternative targeted REA baseline succeeds'; unresolved = 'Third exact label UNKNOWN; no native business-function recovery; Go overwritten metadata remains unrecovered'; }
  } else if (['python.ts', 'jvm-bytecode.ts', 'dotnet-managed.ts', 'apple-plist.ts', 'archive.ts', 'android-manifest.ts', 'android-r8.ts', 'sourcemap.ts'].includes(name)) {
    group = 'containers'; observation = 'Three-seed selected official-provider/container tasks independently corroborated; most baselines already work';
    unresolved = 'Execution/signatures/installability and full equivalence UNKNOWN; historical directory provenance incomplete';
    if (name === 'apple-plist.ts') unresolved = 'XML official-reader task succeeds; protected binary plist recovery UNKNOWN';
    if (name === 'sourcemap.ts') { observation = 'Non-injective actual replacement demonstrated: distinct original maps can produce identical protected bytes'; unresolved = 'Original source-map provenance unrecoverable from this carrier alone; no copied-clean-answer recovery'; }
  } else if (['erlang-beam.ts', 'evm-bytecode.ts', 'pcap-capture.ts', 'gpu-ptx.ts', 'mobile-game.ts'].includes(name)) {
    group = 'bytecode'; observation = 'Three-seed selected genuine official-tool tasks; independent raw/provider/re-emission checks';
    unresolved = 'No general bytecode semantics/GPU/native execution claim; typed acceptance gate fix independently re-reviewed';
    if (name === 'mobile-game.ts') unresolved += '; genuine Unity metadata/native pair absent, IL2CPP controls synthetic only';
  } else if (['memory-diff-shield.ts', 'runtime-shield.ts', 'cdp-shape-budget-breaker.ts', 'frida-capture-saturation.ts', 'obligation-flooder.ts', 'diff-noise-injector.ts', 'crash-trace-decoy.ts', 'system-diagnostic-decoy.ts'].includes(name)) {
    group = 'bytecode'; observation = 'Actual contained CDP/Frida selected task plus named helper invocation counts; generated definitions distinguished from invoked code';
    unresolved = 'Actual REA collector saturation, general memory/crash/diff recovery, agent damage and causal module effectiveness UNKNOWN';
  } else if (name === 'format-payloads.ts') {
    group = 'source'; observation = 'Source mapping plus multiple format reports; untrusted embedded claims are retained data';
    unresolved = 'No independent causal or universal cross-format recovery rate';
  }
  modules.push({ path: file.path, sourceSha256: file.sha256, family: file.family, formats: file.artifact_formats,
    status: 'SCOPED_OBSERVATIONS_WITH_UNKNOWN', observation, unresolved, evidence: name === 'go-flutter-exhaustion.ts' ? [...refs[group], ...refs.native] : refs[group],
    comprehensiveRecovery: 'UNKNOWN', moduleCausalAttribution: 'UNKNOWN', projectedMetricsAreMeasurements: false });
}
const referencePaths = [...new Set(Object.values(refs).flat())];
const report = { schema: 'anti-bla.qualification-index/1', generatedUtc: new Date().toISOString(),
  status: 'SCOPED_QUALIFICATION_RECORDED_WITH_UNKNOWN', auditSource: 'controller-index-not-independent-damage-review',
  pins: { bla: inventory.bla, rea: inventory.rea }, sourceInventory: await identity('docs/shield-inventory.json'),
  exactTrackedPathsAndHashes: true, sourceFiles: modules.length, modules,
  researchTrackedStatus: Object.fromEntries(['bla', 'rea'].map(repo => [repo, git(repo, 'status', '--porcelain', '--untracked-files=no')])),
  references: await Promise.all(referencePaths.map(identity)), reviewLedger: await identity('reports/OPEN-REVIEW-ITEMS.json'),
  claimRules: ['Index generation is not a new run or recovery assertion', 'Source coverage is not module effectiveness',
    'Repeated replays are not additional independent seeds', 'Baseline success remains baseline success',
    'Information loss, unsupported cases and unmeasured work stay UNKNOWN', 'No aggregate all-shield bypass/damage/token/cost score'],
  agentEvaluation: 'All three fresh agents recover three held-out selected tasks and benign control; no incremental agent recovery win;194 controller checks and7 contained variants, no efficiency/cost comparison',
  peakRssBytes: null, tokens: null, cost: null };
const destination = path.join(root, 'reports', `C7-coverage-${stamp}.json`);
await writeFile(destination, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ report: destination, status: report.status, sourceFiles: modules.length, references: referencePaths.length }));
