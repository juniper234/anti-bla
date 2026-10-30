import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
const execFileAsync = promisify(execFile);
const cli = path.resolve('dist/cli.js');

test('real MCP initialize/discovery/call agrees with CLI without target writes', { timeout: 20000 }, async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-mcp-'));
  const input = path.join(root, 'sample.bin');
  await writeFile(input, 'abc');
  const before = await readdir(root);
  const client = new Client({ name: 'anti-bla-test-client', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [cli, 'serve', '--root', root], stderr: 'pipe' });
  let stderr = '';
  transport.stderr?.on('data', b => { stderr += b.toString(); });
  t.after(async () => { await client.close(); });
  await client.connect(transport);
  const listing = await client.listTools();
  for (const name of ['capabilities', 'inspect_artifact', 'read_artifact_view']) {
    assert.ok(listing.tools.some(tool => tool.name === name));
  }
  assert.ok(listing.tools.every(tool => tool.annotations.readOnlyHint && !tool.annotations.openWorldHint));
  const mcp = await client.callTool({ name: 'inspect_artifact', arguments: { path: input } });
  const record = JSON.parse(mcp.content[0].text);
  assert.equal(record.status, 'ok');
  assert.equal(mcp._meta.provenance.untrusted_content, true);
  const { stdout } = await execFileAsync(process.execPath, [cli, 'inspect-artifact', input, '--root', root]);
  const command = JSON.parse(stdout);
  assert.deepEqual(command, record);
  assert.equal(record.artifact.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.deepEqual(await readdir(root), before);
  assert.equal(stderr, '');
  const invalid = await client.callTool({ name: 'inspect_artifact', arguments: { path: input, execute: true } });
  assert.equal(invalid.isError, true);
  assert.equal(JSON.parse(invalid.content[0].text).reason.code, 'invalid_request');
  const unknown = await client.callTool({ name: 'arbitrary_command', arguments: {} });
  assert.equal(unknown.isError, true);
});

test('CLI fails closed with no allowed root or unknown flags and keeps stdout JSON', async () => {
  for (const args of [['inspect-artifact', 'input.bin'], ['capabilities', '--root', '.', '--execute']]) {
    let failure;
    try { await execFileAsync(process.execPath, [cli, ...args]); } catch (e) { failure = e; }
    assert.ok(failure);
    assert.equal(failure.code, 2);
    assert.equal(JSON.parse(failure.stdout).status, 'error');
  }
});

test('real MCP cancellation does not prevent a later request', { timeout: 20000 }, async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-cancel-'));
  const input = path.join(root, 'sample.bin');
  await writeFile(input, Buffer.alloc(4 * 1024 * 1024, 65));
  const client = new Client({ name: 'cancellation-test', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [cli, 'serve', '--root', root], stderr: 'pipe' });
  t.after(async () => { await client.close(); });
  await client.connect(transport);
  const controller = new AbortController();
  const pending = client.callTool({ name: 'inspect_artifact', arguments: { path: input } }, undefined, { signal: controller.signal });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(pending);
  // capabilities requires no artifact worker, so cancellation recovery is
  // observed without assuming a particular worker startup duration.
  const next = await client.callTool({ name: 'capabilities', arguments: {} });
  assert.equal(JSON.parse(next.content[0].text).status, 'ok');
});

test('serve startup failure leaves protocol stdout empty and reports stderr', async () => {
  let failure;
  try { await execFileAsync(process.execPath, [cli, 'serve']); } catch (e) { failure = e; }
  assert.ok(failure);
  assert.equal(failure.code, 2);
  assert.equal(failure.stdout, '');
  assert.match(failure.stderr, /invalid_request/);
});

test('MCP exposes its separate wire budget and refuses an oversized outbound frame', { timeout: 10000 }, async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-wire-'));
  const child = spawn(process.execPath, [cli, 'serve', '--root', root, '--max-output-bytes', '1024'], { stdio: ['pipe','pipe','pipe'] });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  const frames = [];
  let pending = '';
  let capability;
  let hugeId = '';
  child.stdout.on('data', chunk => {
    pending += chunk.toString();
    while (pending.includes('\n')) {
      const end = pending.indexOf('\n');
      const line = pending.slice(0, end);
      pending = pending.slice(end + 1);
      frames.push(Buffer.byteLength(line) + 1);
      const response = JSON.parse(line);
      if (response.id === 1) {
        child.stdin.write(JSON.stringify({ jsonrpc:'2.0', method:'notifications/initialized' }) + '\n');
        child.stdin.write(JSON.stringify({ jsonrpc:'2.0', id:2, method:'tools/call', params:{ name:'capabilities', arguments:{} } }) + '\n');
      } else if (response.id === 2) {
        capability = JSON.parse(response.result.content[0].text);
        // Independently choose an ID whose response JSON is exactly at the
        // wire ceiling; the required newline must make it inadmissible.
        hugeId = 'r'.repeat(16384 - Buffer.byteLength(JSON.stringify({ ...response, id: '' })));
        child.stdin.write(JSON.stringify({ jsonrpc:'2.0', id:hugeId, method:'tools/call', params:{ name:'capabilities', arguments:{} } }) + '\n');
      } else if (response.id === hugeId) child.stdin.end();
    }
  });
  child.stdin.on('error', () => {});
  child.stdin.write(JSON.stringify({ jsonrpc:'2.0', id:1, method:'initialize', params:{ protocolVersion:'2025-11-25', capabilities:{}, clientInfo:{name:'wire-test',version:'1'} } }) + '\n');
  await new Promise((resolve, reject) => { child.once('exit', resolve); child.once('error', reject); });
  assert.ok(capability);
  assert.equal(capability.maxMcpFrameBytes, 16384);
  assert.ok(frames.every(bytes => bytes <= 16384), `oversized frame: ${Math.max(...frames)}`);
});
