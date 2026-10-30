import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { AnalysisService } from '../dist/service.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
const run=promisify(execFile);

async function own(source) {
  const root=await mkdtemp(path.join(tmpdir(),'anti-bla-js-integration-'));
  const target=path.join(root,'controlled.mjs');
  await writeFile(target,source);
  return {root,target,service:await AnalysisService.create({roots:[root]})};
}

test('requested JavaScript roots/facts are paged through real CLI/MCP with explicit assumptions',async t=>{
  const {root,target,service}=await own('export function register(router){router.get("/api/example",()=>1);}');
  const args={path:target,entryExport:'register',section:'facts',limit:20};
  const result=await service.run('inspect_javascript',args);
  assert.equal(result.status,'ok');
  assert.ok(result.analysis.page.items.some(f=>f.value==='/api/example'));
  assert.equal(result.analysis.assumeStandardIntrinsics,false);
  assert.equal(result.behavioralEquivalence,'unknown');
  const cli=path.resolve('dist/cli.js');
  const {stdout}=await run(process.execPath,[cli,'inspect-javascript',target,'--root',root,'--entry-export','register','--section','facts','--limit','20']);
  assert.deepEqual(JSON.parse(stdout),result);
  const client=new Client({name:'js-integration',version:'1'});
  const transport=new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'});
  t.after(()=>client.close()); await client.connect(transport);
  const actual=await client.callTool({name:'inspect_javascript',arguments:args});
  assert.deepEqual(JSON.parse(actual.content[0].text),result);
  assert.equal(actual._meta.provenance.untrusted_content,true);
});

test('normalized source is a bounded derivative view with original provenance and no file writes',async()=>{
  const original='export function value(){return 1+2;}';
  const expected='export function value(){return 3;}';
  const {target,service}=await own(original);
  const r=await service.run('read_normalized_javascript',{path:target,entryExport:'value',length:1024});
  assert.equal(r.status,'ok');
  assert.equal(Buffer.from(r.analysis.view.base64,'base64').toString(),expected);
  assert.equal(r.analysis.derivative.sha256,createHash('sha256').update(expected).digest('hex'));
  assert.equal(r.analysis.scope,'inspection-only');
  assert.equal(r.analysis.fullEquivalence,'UNKNOWN');
  assert.equal(await readFile(target,'utf8'),original);
  assert.equal((await service.run('inspect_javascript',{path:target,assumeStandardIntrinsics:1})).reason.code,'invalid_request');
});

test('refused JavaScript normalization never returns an empty substitute or successful byte view',async()=>{
  const {target,service}=await own('export {');
  const r=await service.run('read_normalized_javascript',{path:target});
  assert.equal(r.status,'unknown');
  assert.equal(r.analysis.view,undefined);
  assert.equal(r.analysis.derivative,null);
});
