import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';

// Local distribution acceptance only. Never publishes, writes client settings,
// runs lifecycle scripts, or executes an input artifact.
const root = path.resolve(import.meta.dirname, '..');
const stamp = new Date().toISOString().replaceAll(':', '-');
const release = path.join(root, 'artifacts', 'release', stamp);
const work = path.join(root, 'scratch', 'package smoke', stamp);
const reportPath = path.join(root, 'reports', `C8-package-${stamp}.json`);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const identity = async file => { const b = await readFile(file); return { path: file, bytes: b.length, sha256: sha(b) }; };
const npm = process.env.ANTI_BLA_NPM_CLI ?? path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
const report = { schema: 'anti-bla.package-smoke/1', startedUtc: new Date().toISOString(), status: 'IN_PROGRESS',
  root, release, work, node: { executable: process.execPath, version: process.version }, commands: [], checks: [],
  targetExecution: false, globalConfigurationWrites: false, publication: false,
  limitations: ['Local development preview, not a registry publication or universal bypass',
    'No total peak RSS or model token/cost measurement; these fields remain null',
    'Plugin manifests are exercised as local configurations, not a live global plugin installation'] };
await mkdir(release, { recursive: true });
await mkdir(work, { recursive: true });
const cache = path.join(work, 'npm cache');
const temp = path.join(work, 'temporary files');
await mkdir(temp);
const userconfig = path.join(work, 'empty-user.npmrc');
await writeFile(userconfig, '', { flag: 'wx' });
const env = { ...process.env, TEMP: temp, TMP: temp, npm_config_cache: cache, npm_config_userconfig: userconfig };
const check = (name, condition, evidence) => { report.checks.push({ name, passed: Boolean(condition), evidence }); assert.ok(condition, name); };

async function command(name, executable, args, cwd = root, accepted = [0]) {
  const startedUtc = new Date().toISOString();
  const start = performance.now();
  const stdoutPath = path.join(work, `${report.commands.length}-${name}.stdout`);
  const stderrPath = path.join(work, `${report.commands.length}-${name}.stderr`);
  const chunks = [[], []];
  let captureBytes = 0, captureLimit = false, timedOut = false;
  const child = spawn(executable, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  const timer = setTimeout(() => { timedOut = true; child.kill(); }, 120_000);
  const error = await new Promise(resolve => {
    [child.stdout, child.stderr].forEach((stream, index) => stream.on('data', bytes => {
      captureBytes += bytes.length;
      if (captureBytes > 16 * 1024 * 1024) { captureLimit = true; child.kill(); }
      else chunks[index].push(bytes);
    }));
    child.once('error', resolve);
    child.once('close', () => resolve(null));
  });
  clearTimeout(timer);
  const stdout = Buffer.concat(chunks[0]);
  const stderr = Buffer.concat(chunks[1]);
  await writeFile(stdoutPath, stdout, { flag: 'wx' });
  await writeFile(stderrPath, stderr, { flag: 'wx' });
  const record = { name, command: [executable, ...args], cwd, startedUtc, wallMs: performance.now() - start,
    exitCode: child.exitCode, signal: child.signalCode, timedOut, captureLimit, error: error ? String(error) : null,
    stdout: await identity(stdoutPath), stderr: await identity(stderrPath), peakRssBytes: null };
  report.commands.push(record);
  assert.ok(!error && !timedOut && !captureLimit && accepted.includes(child.exitCode), `${name}: exit ${child.exitCode}`);
  return { record, stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') };
}

async function smokeClient(name, Client, Transport, options, input, cliResult, workspace) {
  const client = new Client({ name: `anti-bla-installed-${name}`, version: '1' });
  const transport = new Transport({ ...options, stderr: 'pipe' });
  let errors = '';
  transport.stderr?.on('data', bytes => { errors += bytes.toString(); });
  const record = { name, command: [options.command, ...options.args], cwd: options.cwd, calls: [], closeCompleted: false };
  report.clients ??= [];
  report.clients.push(record);
  try {
    await client.connect(transport);
    const list = await client.listTools();
    record.tools = list.tools.map(t => ({ name: t.name, annotations: t.annotations }));
    check(`${name}: default or opt-in discovery`, list.tools.some(t => t.name === 'prepare_javascript_view') === Boolean(workspace));
    check(`${name}: precise write annotation`, list.tools.every(t => t.annotations.readOnlyHint === (t.name !== 'prepare_javascript_view')));
    const call = async (operation, args) => {
      const response = await client.callTool({ name: operation, arguments: args });
      const result = JSON.parse(response.content[0].text);
      record.calls.push({ operation, args, response });
      return result;
    };
    const result = await call('inspect_artifact', { path: input });
    check(`${name}: installed CLI/MCP parity`, JSON.stringify(result) === JSON.stringify(cliResult));
    const outside = await call('inspect_artifact', { path: path.join(root, 'package.json') });
    check(`${name}: outside scope refuses`, outside.reason?.code === 'outside_root');
    if (workspace) {
      const prepared = await call('prepare_javascript_view', { path: path.join(path.dirname(input), 'owned.mjs'), entryExport: 'register' });
      record.prepared = prepared;
      check(`${name}: explicit export complete`, prepared.status === 'ok' && prepared.sidecar.completion === 'complete');
      const sidecar = prepared.sidecar;
      const view = await identity(sidecar.viewPath);
      const evidence = await identity(sidecar.evidencePath);
      record.exportIdentity = { view, evidence };
      check(`${name}: view under workspace`, path.relative(workspace, sidecar.viewPath).split(path.sep)[0].startsWith('anti-bla-view-'));
      check(`${name}: output hash`, view.sha256 === sidecar.derivativeSha256);
      check(`${name}: evidence hash`, evidence.sha256 === sidecar.evidenceSha256);
      const manifest = JSON.parse(await readFile(sidecar.evidencePath, 'utf8'));
      record.manifest = manifest;
      check(`${name}: complete evidence record`, manifest.completion === 'complete');
    } else {
      const large = path.join(path.dirname(input), 'cancel.bin');
      await writeFile(large, Buffer.alloc(64 * 1024 * 1024, 65), { flag: 'wx' });
      const controller = new AbortController();
      const pending = client.callTool({ name: 'inspect_artifact', arguments: { path: large } }, undefined, { signal: controller.signal });
      const timer = setTimeout(() => controller.abort(), 30);
      let rejected = false;
      try { await pending; } catch (error) { rejected = true; record.cancellation = { clientError: String(error) }; }
      finally { clearTimeout(timer); }
      check(`${name}: client abort observed`, rejected);
      let next;
      for (let attempt = 0; attempt < 100; attempt++) {
        next = await call('inspect_artifact', { path: input });
        if (next.reason?.code !== 'busy') break;
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      check(`${name}: actual analysis after cancellation`, next.status === 'ok' && next.artifact.sha256 === cliResult.artifact.sha256);
    }
  } finally {
    await client.close();
    record.closeCompleted = true;
    record.stderr = errors;
  }
  check(`${name}: no diagnostic/protocol contamination`, errors === '');
}

try {
  report.npm = { executable: npm, version: (await command('npm-version', process.execPath, [npm, '--version'])).stdout.trim(), identity: await identity(npm) };
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const shrinkwrap = JSON.parse(await readFile(path.join(root, 'npm-shrinkwrap.json'), 'utf8'));
  check('private distribution and matching lock identity', pkg.private === true && pkg.name === shrinkwrap.name && pkg.version === shrinkwrap.version);
  const packed = JSON.parse((await command('pack', process.execPath, [npm, 'pack', '--json', '--ignore-scripts', '--pack-destination', release, '--cache', cache])).stdout)[0];
  const tarball = path.join(release, packed.filename);
  const bytes = await readFile(tarball);
  report.tarball = { ...await identity(tarball), integrity: 'sha512-' + createHash('sha512').update(bytes).digest('base64'), npmMetadata: packed };
  check('tarball integrity agrees with npm', report.tarball.integrity === packed.integrity);
  const entries = execFileSync('tar', ['-tzf', tarball], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }).trim().split(/\r?\n/);
  const files = entries.filter(p => !p.endsWith('/'));
  const allowed = /^(?:package\/(?:package\.json|npm-shrinkwrap\.json|README\.md|LICENSE|THIRD_PARTY_NOTICES\.md|\.mcp\.json)|package\/(?:dist\/[A-Za-z0-9_/-]+\.(?:js|d\.ts|js\.map)|skills\/anti-bla\/SKILL\.md|\.codex-plugin\/(?:plugin|mcp)\.json|\.claude-plugin\/plugin\.json|scripts\/plugin-mcp-launcher\.mjs|assets\/readme-hero\.svg|examples\/routes\.mjs|docs\/(?:COVERAGE|SIDECARS|GENUINE-FRAMEWORKS|RESEARCH|JAVASCRIPT|ASAR|NATIVE|DATA-FORMATS|SHIELD-INVENTORY)\.md|docs\/shield-inventory\.json|reports\/(?:README\.md|v0\.1-summary\.json)))$/;
  check('strict tarball whitelist and no traversal/duplicates', new Set(files).size === files.length && files.every(p => allowed.test(p) && !p.split('/').includes('..')), files);
  const required = ['package.json', 'npm-shrinkwrap.json', 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'dist/cli.js', 'dist/server.js', 'skills/anti-bla/SKILL.md', '.codex-plugin/plugin.json', '.codex-plugin/mcp.json', '.claude-plugin/plugin.json', '.mcp.json', 'scripts/plugin-mcp-launcher.mjs', 'assets/readme-hero.svg', 'examples/routes.mjs', 'docs/COVERAGE.md', 'docs/SIDECARS.md', 'docs/GENUINE-FRAMEWORKS.md', 'docs/RESEARCH.md', 'reports/README.md', 'reports/v0.1-summary.json'];
  check('all distribution entrypoints included', required.every(p => files.includes(`package/${p}`)));
  report.packedFileIdentities = files.map(file => {
    const b = execFileSync('tar', ['-xOzf', tarball, file], { maxBuffer: 4 * 1024 * 1024 });
    if (file.endsWith('.map')) check(`${file}: no embedded source corpus`, !Object.hasOwn(JSON.parse(b), 'sourcesContent'));
    return { path: file, bytes: b.length, sha256: sha(b) };
  });
  const clientDir = path.join(work, 'isolated client');
  await mkdir(clientDir);
  await command('isolated-install', process.execPath, [npm, 'install', '--prefix', clientDir, tarball, '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', '--cache', cache]);
  const installed = path.join(clientDir, 'node_modules', 'anti-bla');
  report.installedPackage = installed;
  const installedPkg = JSON.parse(await readFile(path.join(installed, 'package.json'), 'utf8'));
  const cli = path.join(installed, installedPkg.bin['anti-bla']);
  check('installed CLI exists with shebang', (await stat(cli)).isFile() && (await readFile(cli, 'utf8')).startsWith('#!/usr/bin/env node'));
  for (const file of report.packedFileIdentities) {
    check(`installed bytes: ${file.path}`, (await identity(path.join(installed, file.path.slice('package/'.length)))).sha256 === file.sha256);
  }
  check('no source checkout or test payload installed', !(await readdir(installed)).some(p => ['research', 'scratch', 'src', 'test', '.runtime', '.tools'].includes(p)));
  check('only curated public reports installed', JSON.stringify((await readdir(path.join(installed, 'reports'))).sort()) === JSON.stringify(['README.md', 'v0.1-summary.json']));
  const artifactRoot = path.join(work, 'owned inputs');
  const workspace = path.join(work, 'explicit views');
  await mkdir(artifactRoot); await mkdir(workspace);
  const input = path.join(artifactRoot, 'sample.bin');
  const js = path.join(artifactRoot, 'owned.mjs');
  await writeFile(input, 'abc', { flag: 'wx' });
  await writeFile(js, 'export function register(router) { return router.post("/api/owned/package-smoke", 42); }\n', { flag: 'wx' });
  const original = await identity(js);
  const callCli = async (name, args, codes) => JSON.parse((await command(name, process.execPath, [cli, ...args], clientDir, codes)).stdout);
  check('bare installed help', (await callCli('help', ['--help'])).status === 'ok');
  const version = (await command('version', process.execPath, [cli, '--version'], clientDir)).stdout.trim();
  check('installed version identity', version === pkg.version);
  const capabilities = await callCli('default-capabilities', ['capabilities', '--root', artifactRoot]);
  check('default package has no write operation', capabilities.analysisWrites === false && !capabilities.operations.includes('prepare_javascript_view'));
  const result = await callCli('inspect', ['inspect-artifact', input, '--root', artifactRoot]);
  check('installed artifact SHA', result.artifact.sha256 === sha(Buffer.from('abc')));
  const setup = await callCli('setup', ['setup', '--root', artifactRoot, '--dry-run']);
  check('setup points to installed skill', setup.writes === false && setup.skill.path === path.join(installed, 'skills', 'anti-bla', 'SKILL.md'));
  check('installed skill readable', (await readFile(setup.skill.path, 'utf8')).includes('name: anti-bla'));
  const refusal = await callCli('default-export-refuses', ['prepare-javascript-view', js, '--root', artifactRoot], [2, 3]);
  check('default export requires workspace', refusal.reason?.code === 'workspace_required' && (await readdir(workspace)).length === 0);
  const requireInstalled = createRequire(path.join(installed, 'package.json'));
  const { Client } = await import(pathToFileURL(requireInstalled.resolve('@modelcontextprotocol/sdk/client/index.js')).href);
  const { StdioClientTransport } = await import(pathToFileURL(requireInstalled.resolve('@modelcontextprotocol/sdk/client/stdio.js')).href);
  report.installedSdk = requireInstalled.resolve('@modelcontextprotocol/sdk/client/index.js');
  check('MCP client uses isolated installed dependency', report.installedSdk.startsWith(clientDir + path.sep));
  const plugin = JSON.parse(await readFile(path.join(installed, '.codex-plugin', 'plugin.json'), 'utf8'));
  const config = JSON.parse(await readFile(path.resolve(installed, plugin.mcpServers), 'utf8'));
  const entry = config.mcpServers['anti-bla'];
  const options = { command: process.execPath, args: entry.args, cwd: path.resolve(installed, entry.cwd), env: { TEMP: temp, TMP: temp, ANTI_BLA_ARTIFACT_ROOT: artifactRoot } };
  await smokeClient('manifest-default', Client, StdioClientTransport, options, input, result);
  const optIn = await callCli('opt-in-setup', ['setup', '--root', artifactRoot, '--workspace', workspace, '--dry-run']);
  check('opt-in proposal exact argv', JSON.stringify(optIn.mcp.mcpServers['anti-bla'].args) === JSON.stringify([cli, 'serve', '--root', artifactRoot, '--workspace', workspace]));
  await smokeClient('manifest-opt-in', Client, StdioClientTransport, { ...options, env: { ...options.env, ANTI_BLA_WORKSPACE: workspace } }, input, result, workspace);
  check('original unchanged', (await identity(js)).sha256 === original.sha256);
  report.fixtureIdentities = [await identity(input), original, await identity(js)];
  report.status = 'LOCAL_PACKAGE_VERIFIED';
} catch (error) {
  report.status = 'FAIL';
  report.failure = { name: error.name, message: error.message, stack: error.stack };
  process.exitCode = 1;
} finally {
  report.finishedUtc = new Date().toISOString();
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ report: reportPath, status: report.status, tarball: report.tarball?.path, checks: report.checks.length, failed: report.failure?.message }));
}
