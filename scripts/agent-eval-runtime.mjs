import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

// Trusted fixed-fixture runner for all agent-evaluation lanes equally. Not a
// product operation or arbitrary-target API. Exact artifacts must be unchanged.
const [manifestPath, selected] = process.argv.slice(2);
assert.ok(manifestPath && /^[1-4]$/.test(selected ?? ''), 'manifest + case index required');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
assert.equal(manifest.schema, 'anti-bla.agent-lane/1');
const fixture = manifest.inputs.find(row => row.index === Number(selected));
assert.ok(fixture);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
for (const identity of [fixture.artifact, fixture.runner]) assert.equal(sha(await readFile(identity.path)), identity.sha256);
const out = path.join(manifest.laneRoot, 'runtime-observations', `${selected}-${randomUUID()}`);
await mkdir(out, { recursive: true });
const report = { schema: 'anti-bla.agent-runtime/1', selected: Number(selected), lane: manifest.lane, commands: [], result: 'UNKNOWN', fixture };
async function run(label, args) {
  const chunks = [[], []], start = performance.now(), startedUtc = new Date().toISOString();
  const child = spawn('docker', ['--context', 'desktop-linux', ...args], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let limit = false, timedOut = false, bytes = 0;
  [child.stdout, child.stderr].forEach((stream, i) => stream.on('data', data => { bytes += data.length; if (bytes > 1024 * 1024) { limit = true; child.kill(); } else chunks[i].push(data); }));
  const timer = setTimeout(() => { timedOut = true; child.kill(); }, 60_000);
  let error;
  await new Promise(resolve => { child.once('error', e => { error = String(e); resolve(); }); child.once('close', resolve); });
  clearTimeout(timer);
  const [stdout, stderr] = chunks.map(list => Buffer.concat(list));
  const record = { command: ['docker', '--context', 'desktop-linux', ...args], startedUtc, wallMs: performance.now() - start,
    exitCode: child.exitCode, signal: child.signalCode, timedOut, limit, error: error ?? null,
    stdout: { path: path.join(out, `${label}.stdout`), bytes: stdout.length, sha256: sha(stdout) },
    stderr: { path: path.join(out, `${label}.stderr`), bytes: stderr.length, sha256: sha(stderr) }, peakTargetRss: null };
  await writeFile(record.stdout.path, stdout, { flag: 'wx' }); await writeFile(record.stderr.path, stderr, { flag: 'wx' });
  report.commands.push(record);
  assert.ok(!error && !limit && !timedOut && child.exitCode === 0, `${label} failed`);
  return stdout.toString('utf8');
}
const name = `anti-bla-agent-${randomUUID()}`;
let created = false;
try {
  await run('create', ['create', '--name', name, '--label', 'anti-bla.agent-eval=true', '--pull', 'never', '--platform', 'linux/amd64',
    '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '256m', '--cpus', '1',
    '--user', '65534:65534', '--mount', `type=bind,source=${fixture.inputDirectory},target=/fixture,readonly`, '--workdir', '/fixture', '--entrypoint', 'node',
    'node@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea', '/fixture/runner.mjs']);
  created = true;
  const config = JSON.parse(await run('inspect', ['inspect', name]))[0];
  assert.ok(config.HostConfig.NetworkMode === 'none' && config.HostConfig.ReadonlyRootfs && config.Config.User === '65534:65534' &&
    config.HostConfig.CapDrop.includes('ALL') && !config.HostConfig.Privileged && !config.HostConfig.CapAdd?.length &&
    config.HostConfig.SecurityOpt.includes('no-new-privileges') && config.HostConfig.PidsLimit === 64 && config.HostConfig.Memory === 268435456 &&
    config.HostConfig.NanoCpus === 1e9 && config.Mounts.length === 1 && config.Mounts[0].RW === false);
  const observed = JSON.parse((await run('execute', ['start', '--attach', name])).trim());
  assert.equal(observed.schema, 'owned-agent-runtime/1');
  assert.equal(observed.containment.NoNewPrivs, '1'); assert.equal(observed.containment.Seccomp, '2');
  assert.ok(['CapEff', 'CapPrm', 'CapBnd'].every(k => /^0+$/.test(observed.containment[k])));
  report.observation = observed;
  report.result = 'OBSERVED';
} catch (error) { report.error = String(error); process.exitCode = 1; }
finally {
  if (created) {
    try { await run('cleanup', ['rm', '--force', name]); report.remaining = (await run('remaining', ['ps', '-a', '--filter', `name=^/${name}$`, '--format', '{{.ID}}'])).trim(); assert.equal(report.remaining, ''); }
    catch (error) { report.cleanupError = String(error); report.result = 'UNKNOWN'; process.exitCode = 1; }
  }
  for (const identity of [fixture.artifact, fixture.runner]) assert.equal(sha(await readFile(identity.path)), identity.sha256);
  const destination = path.join(out, 'observation.json');
  await writeFile(destination, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ report: destination, result: report.result, observation: report.observation, error: report.error }));
}
