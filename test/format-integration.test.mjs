import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { AnalysisService } from '../dist/service.js';
import { pe } from './helpers/native-fixtures.mjs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
const run=promisify(execFile);

test('native/wasm/model adapters retain literal findings through service CLI and real MCP',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'anti-bla-formats-'));
  const service=await AnalysisService.create({roots:[root]});
  const header=Buffer.from('{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}');
  const padded=Buffer.concat([header,Buffer.alloc((8-header.length%8)%8,32)]);
  const model=Buffer.alloc(8+padded.length+8); model.writeBigUInt64LE(BigInt(padded.length)); padded.copy(model,8);
  model.writeFloatLE(1.25,8+padded.length);model.writeFloatLE(-2,12+padded.length);
  const cases=[
    {name:'inspect_native',file:'own.exe',bytes:pe(),args:{},check:r=>assert.equal(r.analysis.entrypoint.fileOffset,512)},
    {name:'inspect_wasm',file:'own.wasm',bytes:Buffer.from('0061736d010000000105016000017f03020100070501016600000a06010400412a0b','hex'),args:{exportName:'f'},check:r=>assert.equal(r.analysis.selected.body.base64,'AEEqCw==')},
    {name:'inspect_model',file:'own.safetensors',bytes:model,args:{tensor:'w'},check:r=>assert.deepEqual(r.analysis.selected.values,[1.25,-2])},
  ];
  const cli=path.resolve('dist/cli.js');
  const client=new Client({name:'formats-integration',version:'1'});
  const transport=new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'});
  t.after(()=>client.close());await client.connect(transport);
  const list=await client.listTools();
  for(const c of cases){
    const file=path.join(root,c.file);await writeFile(file,c.bytes);
    const args={path:file,...c.args};const expected=await service.run(c.name,args);
    assert.equal(expected.status,'ok');c.check(expected);
    assert.equal(expected.behavioralEquivalence,'unknown');
    assert.ok(list.tools.some(t=>t.name===c.name));
    const mcp=await client.callTool({name:c.name,arguments:args});assert.deepEqual(JSON.parse(mcp.content[0].text),expected);
    const extra=c.args.exportName?['--export-name',c.args.exportName]:c.args.tensor?['--tensor',c.args.tensor]:[];
    const {stdout}=await run(process.execPath,[cli,c.name.replaceAll('_','-'),file,'--root',root,...extra]);
    assert.deepEqual(JSON.parse(stdout),expected);
  }
});

test('explicit format tools reject malformed data and invalid selection bounds before claiming recovery',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'anti-bla-formats-bad-'));
  const file=path.join(root,'broken.bin');await writeFile(file,'abc');
  const service=await AnalysisService.create({roots:[root]});
  for(const op of ['inspect_native','inspect_wasm','inspect_model','inspect_sqlite']){
    const r=await service.run(op,{path:file});assert.notEqual(r.status,'ok');
    assert.equal(r.artifact.bytes,3);
  }
  assert.equal((await service.run('inspect_wasm',{path:file,limit:101})).reason.code,'invalid_request');
  assert.equal((await service.run('inspect_model',{path:file,tensor:'w',limit:4097})).reason.code,'invalid_request');
  assert.equal((await service.run('inspect_sqlite',{path:file,table:'t',sql:'DROP TABLE t'})).reason.code,'invalid_request');
});
