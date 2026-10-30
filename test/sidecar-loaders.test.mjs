import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { watch } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { AnalysisService } from '../dist/service.js';
const cli = path.resolve('dist/cli.js'), run = promisify(execFile);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const cases = [
  {loader:'js', filename:'inspection.mjs', source:'export function register(router){router.post("/api/invoice/status",()=>{});}'},
  {loader:'jsx', filename:'inspection.jsx', source:'export function register(router){router.post("/api/invoice/status",()=> <span/>);}'},
  {loader:'ts', filename:'inspection.ts', source:'export function register(router: any): void {router.post("/api/invoice/status",()=>{});}'},
  {loader:'tsx', filename:'inspection.tsx', source:'export function register(router: any): void {router.post("/api/invoice/status",()=> <span/>);}'},
];
async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'anti-bla-sidecar-loader-'));
  const workspace = path.join(root, 'views'); await mkdir(workspace);
  // Input suffix does not choose the output name; the admitted loader does.
  const file = path.join(root, 'original.artifact');
  return {root, workspace, file};
}
for (const control of cases) {
  test(`sidecar ${control.loader} API preserves exact syntax in its fixed filename and manifest`, async t => {
    const {root,workspace,file} = await fixture(); await writeFile(file,control.source);
    const service = await AnalysisService.create({roots:[root],workspace}); t.after(() => service.close());
    const r = await service.run('prepare_javascript_view',{path:file,loader:control.loader});
    assert.equal(r.status,'ok'); assert.equal(r.sidecar.completion,'complete');
    assert.equal(path.basename(r.sidecar.viewPath),control.filename);
    const bytes = await readFile(r.sidecar.viewPath), evidence = await readFile(r.sidecar.evidencePath);
    assert.equal(bytes.toString(),control.source); assert.equal(r.sidecar.derivativeSha256,sha(control.source));
    const manifest = JSON.parse(evidence);
    assert.equal(manifest.derivative.filename,control.filename);
    assert.equal(manifest.selection.loader,control.loader);
    assert.equal(manifest.derivative.sha256,sha(control.source));
    assert.equal(r.sidecar.evidenceSha256,sha(evidence));
    assert.deepEqual((await readdir(r.sidecar.viewDirectory)).sort(),['evidence.json',control.filename].sort());
    assert.equal(await readFile(file,'utf8'),control.source);
  });
  test(`sidecar ${control.loader} worker errors and parent deadlines use the same fixed locator`, async t => {
    const {root,workspace,file} = await fixture();
    const service = await AnalysisService.create({roots:[root],workspace}); t.after(() => service.close());
    const missing = await service.run('prepare_javascript_view',{path:file,loader:control.loader});
    assert.equal(missing.status,'error'); assert.equal(missing.reason.code,'not_found');
    assert.equal(path.basename(missing.sidecar.viewPath),control.filename);
    assert.equal(missing.sidecar.completion,'unknown'); assert.equal(missing.sidecar.handoffAllowed,false);
    await writeFile(file,control.source);
    const timed = await AnalysisService.create({roots:[root],workspace,limits:{timeoutMs:1}}); t.after(() => timed.close());
    const deadline = await timed.run('prepare_javascript_view',{path:file,loader:control.loader});
    assert.equal(deadline.status,'unknown'); assert.equal(deadline.reason.code,'deadline');
    assert.equal(path.basename(deadline.sidecar.viewPath),control.filename);
    assert.equal(deadline.sidecar.handoffAllowed,false);
  });
}
test('sidecar TSX cancellation after reservation and output preflight keep the admitted filename', async t => {
  const control = cases[3], {root,workspace,file} = await fixture(); await writeFile(file,control.source);
  const small = await AnalysisService.create({roots:[root],workspace,limits:{maxOutputBytes:1024}}); t.after(() => small.close());
  const refused = await small.run('prepare_javascript_view',{path:file,loader:'tsx'});
  assert.equal(refused.reason.code,'output_limit'); assert.deepEqual(await readdir(workspace),[]);
  assert.equal(path.basename(refused.sidecar.viewPath),'inspection.tsx');
  const service = await AnalysisService.create({roots:[root],workspace}); t.after(() => service.close());
  const controller = new AbortController();
  const watcher = watch(workspace,(_event,name) => {if (name?.toString().startsWith('anti-bla-view-')) controller.abort();});
  t.after(() => watcher.close());
  const r = await service.run('prepare_javascript_view',{path:file,loader:'tsx'},{signal:controller.signal});
  assert.equal(r.reason.code,'cancelled'); assert.equal(r.sidecar.completion,'unknown');
  assert.equal(path.basename(r.sidecar.viewPath),'inspection.tsx'); assert.equal(r.sidecar.handoffAllowed,false);
});
test('sidecar loader CLI and actual MCP return fixed syntax filenames, with unchanged opt-in discovery', async t => {
  const {root,workspace,file} = await fixture();
  const client = new Client({name:'sidecar-loader-client',version:'1'});
  const transport = new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root,'--workspace',workspace],stderr:'pipe'});
  t.after(() => client.close()); await client.connect(transport);
  const tool = (await client.listTools()).tools.find(t => t.name === 'prepare_javascript_view');
  assert.equal(tool.annotations.readOnlyHint,false);
  assert.deepEqual(tool.inputSchema.properties.loader.enum,['js','jsx','ts','tsx']);
  assert.equal(tool.inputSchema.additionalProperties,false);
  for (const control of cases) {
    await writeFile(file,control.source);
    const {stdout,stderr} = await run(process.execPath,[cli,'prepare-javascript-view',file,'--root',root,'--workspace',workspace,'--loader',control.loader]);
    assert.equal(stderr,''); const fromCli = JSON.parse(stdout);
    const fromMcp = JSON.parse((await client.callTool({name:'prepare_javascript_view',arguments:{path:file,loader:control.loader}})).content[0].text);
    for (const result of [fromCli,fromMcp]) {
      assert.equal(result.status,'ok'); assert.equal(path.basename(result.sidecar.viewPath),control.filename);
      assert.equal(result.sidecar.derivativeSha256,sha(control.source));
      assert.equal(await readFile(result.sidecar.viewPath,'utf8'),control.source);
    }
  }
  const before = await readdir(workspace);
  const denied = JSON.parse((await client.callTool({name:'prepare_javascript_view',arguments:{path:file,loader:'../custom'}})).content[0].text);
  assert.equal(denied.reason.code,'invalid_request'); assert.deepEqual(await readdir(workspace),before);
});
