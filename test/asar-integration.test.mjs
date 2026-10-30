import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { AnalysisService } from '../dist/service.js';
const run = promisify(execFile);

function ownArchive() {
  const json = Buffer.from('{"files":{"main.js":{"size":3,"offset":"0"}}}');
  const padded = Math.ceil(json.length / 4) * 4;
  const out = Buffer.alloc(16 + padded + 3);
  out.writeUInt32LE(4, 0); out.writeUInt32LE(8 + padded, 4);
  out.writeUInt32LE(4 + padded, 8); out.writeUInt32LE(json.length, 12);
  json.copy(out, 16); out.write('abc', 16 + padded);
  return out;
}

test('ASAR registration exposes validated listing and exact member views through service/CLI/MCP', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-asar-integration-'));
  const input = path.join(root, 'app.asar');
  await writeFile(input, ownArchive());
  const service = await AnalysisService.create({ roots: [root] });
  const listing = await service.run('inspect_asar', { path: input });
  assert.equal(listing.status, 'ok');
  assert.equal(listing.analysis.totalEntries, 1);
  const args = { path: input, memberPath: 'main.js', offset: 0, length: 3 };
  const result = await service.run('read_asar_entry', args);
  assert.equal(result.status, 'ok');
  assert.equal(result.analysis.view.base64, 'YWJj');
  assert.equal(result.behavioralEquivalence, 'unknown');
  const cli = path.resolve('dist/cli.js');
  const { stdout } = await run(process.execPath, [cli, 'read-asar-entry', input, '--root', root, '--member-path', 'main.js', '--offset', '0', '--length', '3']);
  assert.deepEqual(JSON.parse(stdout), result);
  const client = new Client({ name:'asar-integration-test',version:'1' });
  const transport = new StdioClientTransport({ command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe' });
  t.after(() => client.close());
  await client.connect(transport);
  const tools = await client.listTools();
  assert.ok(tools.tools.some(tool => tool.name === 'inspect_asar'));
  assert.ok(tools.tools.some(tool => tool.name === 'read_asar_entry'));
  const mcp = await client.callTool({ name:'read_asar_entry',arguments:args });
  assert.deepEqual(JSON.parse(mcp.content[0].text), result);
  assert.equal(mcp._meta.provenance.untrusted_content, true);
});

test('ASAR structural refusals and invalid options propagate without losing artifact identity', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-asar-refusal-'));
  const input = path.join(root, 'app.asar');
  await writeFile(input, Buffer.from('not an archive'));
  const service = await AnalysisService.create({ roots: [root] });
  const r = await service.run('inspect_asar', { path: input });
  assert.equal(r.status, 'error');
  assert.match(r.artifact.sha256, /^[a-f0-9]{64}$/);
  assert.equal((await service.run('inspect_asar',{path:input,limit:101})).reason.code,'invalid_request');
});
