import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

test('packaged plugin manifest launches a real MCP client against an explicit artifact scope', async t => {
  const pluginRoot=path.resolve('.');
  const plugin=JSON.parse(await readFile('.codex-plugin/plugin.json','utf8'));
  const config=JSON.parse(await readFile(path.resolve(pluginRoot,plugin.mcpServers),'utf8'));
  const entry=config.mcpServers['anti-bla'];
  const root=await mkdtemp(path.join(tmpdir(),'anti-bla-plugin-'));
  const file=path.join(root,'input.bin');
  await writeFile(file,'abc');
  const client=new Client({name:'plugin-manifest-smoke',version:'1'});
  const transport=new StdioClientTransport({command:process.execPath,args:entry.args,cwd:path.resolve(pluginRoot,entry.cwd),
    env:{ANTI_BLA_ARTIFACT_ROOT:root},stderr:'pipe'});
  t.after(()=>client.close());
  await client.connect(transport);
  const tools=await client.listTools();
  assert.ok(tools.tools.some(t=>t.name==='inspect_artifact'));
  const actual=await client.callTool({name:'inspect_artifact',arguments:{path:file}});
  assert.equal(JSON.parse(actual.content[0].text).artifact.sha256,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  const refused=await client.callTool({name:'inspect_artifact',arguments:{path:path.resolve('package.json')}});
  assert.equal(JSON.parse(refused.content[0].text).reason.code,'outside_root');
});
