import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { watch } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
const run = promisify(execFile), cli = path.resolve('dist/cli.js');
test('sidecar default CLI help does not advertise enabled write operations', async () => {
  const {stdout} = await run(process.execPath, [cli, '--help']);
  assert.ok(!JSON.parse(stdout).commands.some(command => command.name === 'prepare-javascript-view'));
});
test('sidecar real CLI and MCP produce matching derivative bytes with explicit write annotations', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-sidecar-client-'));
  const workspace = path.join(root, 'workspace'); await mkdir(workspace);
  const file = path.join(root, 'input.mjs'); await writeFile(file, 'export function f(){return 3+4;}');
  const {stdout, stderr} = await run(process.execPath, [cli, 'prepare-javascript-view', file, '--root', root, '--workspace', workspace]);
  assert.equal(stderr, ''); const direct = JSON.parse(stdout);
  assert.equal(direct.status, 'ok');
  for (const enabled of [false, true]) {
    const client = new Client({ name: 'sidecar-real-client', version: '1' });
    const transport = new StdioClientTransport({ command: process.execPath,
      args: [cli, 'serve', '--root', root, ...(enabled ? ['--workspace', workspace] : [])], stderr: 'pipe' });
    t.after(() => client.close()); await client.connect(transport);
    const discovery = (await client.listTools()).tools;
    const tool = discovery.find(t => t.name === 'prepare_javascript_view');
    assert.equal(Boolean(tool), enabled);
    assert.ok(discovery.filter(t => t !== tool).every(t => t.annotations.readOnlyHint));
    const r = JSON.parse((await client.callTool({ name: 'prepare_javascript_view', arguments: {path: file} })).content[0].text);
    if (!enabled) { assert.equal(r.reason.code, 'workspace_required'); continue; }
    assert.deepEqual(tool.annotations, { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false });
    assert.equal(r.status, 'ok');
    assert.equal(r.sidecar.derivativeSha256, direct.sidecar.derivativeSha256);
    assert.equal(await readFile(r.sidecar.viewPath, 'utf8'), 'export function f(){return 7;}');
  }
});
test('sidecar setup and plugin launcher keep workspace explicit without configuration writes', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-sidecar-setup-'));
  const workspace = path.join(root, 'workspace'); await mkdir(workspace);
  const {stdout} = await run(process.execPath, [cli, 'setup', '--root', root, '--workspace', workspace, '--dry-run']);
  const proposal = JSON.parse(stdout);
  assert.equal(proposal.writes, false);
  assert.deepEqual(proposal.mcp.mcpServers['anti-bla'].args, [cli, 'serve', '--root', root, '--workspace', workspace]);
  assert.equal(proposal.scope.workspace, workspace);
  assert.deepEqual(await readdir(workspace), []);
  const client = new Client({name:'sidecar-plugin-client', version:'1'});
  const transport = new StdioClientTransport({command:process.execPath, args:[path.resolve('scripts/plugin-mcp-launcher.mjs')],
    env:{ANTI_BLA_ARTIFACT_ROOT:root, ANTI_BLA_WORKSPACE:workspace}, stderr:'pipe'});
  t.after(() => client.close()); await client.connect(transport);
  assert.ok((await client.listTools()).tools.some(t => t.name === 'prepare_javascript_view'));
  assert.deepEqual(await readdir(workspace), []);
});

test('sidecar actual MCP cancellation preserves uncertainty and protocol stays usable', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-sidecar-mcp-cancel-'));
  const workspace = path.join(root, 'workspace'); await mkdir(workspace);
  const file = path.join(root, 'input.mjs'); await writeFile(file, 'export function f(){return 3+4;}');
  const client = new Client({ name: 'sidecar-real-cancellation', version: '1' });
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [cli, 'serve', '--root', root, '--workspace', workspace], stderr: 'pipe' });
  t.after(() => client.close()); await client.connect(transport);
  const controller = new AbortController();
  const watcher = watch(workspace, (_event, name) => {
    if (name?.toString().startsWith('anti-bla-view-')) controller.abort();
  });
  t.after(() => watcher.close());
  await assert.rejects(client.callTool({ name: 'prepare_javascript_view', arguments: {path: file} }, undefined, {signal:controller.signal}));
  const caps = JSON.parse((await client.callTool({name:'capabilities', arguments:{}})).content[0].text);
  assert.equal(caps.status, 'ok');
  assert.ok((await readdir(workspace)).some(n => n.startsWith('anti-bla-view-')));
});

test('sidecar refuses an oversized response identifier before any storage side effect', {timeout:10000}, async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-sidecar-wire-'));
  const workspace = path.join(root, 'workspace'); await mkdir(workspace);
  const file = path.join(root, 'input.mjs'); await writeFile(file, 'export function f(){return 3+4;}');
  const child = spawn(process.execPath, [cli, 'serve', '--root', root, '--workspace', workspace, '--max-output-bytes', '8192'],
    {stdio:['pipe','pipe','pipe'],windowsHide:true});
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let pending = '', sent = false;
  child.stdout.on('data', chunk => {
    pending += chunk.toString();
    while (pending.includes('\n')) {
      const end = pending.indexOf('\n'), response = JSON.parse(pending.slice(0, end)); pending = pending.slice(end + 1);
      if (response.id === 1) {
        child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'}) + '\n');
        child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:'r'.repeat(20000),method:'tools/call',params:{name:'prepare_javascript_view',arguments:{path:file}}}) + '\n');
        sent = true;
      } else child.stdin.end();
    }
  });
  child.stdin.on('error', () => {});
  child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'sidecar-wire',version:'1'}}}) + '\n');
  await new Promise((resolve,reject) => {child.once('exit',resolve);child.once('error',reject);});
  assert.equal(sent,true);
  assert.deepEqual(await readdir(workspace), []);
});
