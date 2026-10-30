// Research suite (17 tests): requires the pinned local REA checkout/runtime.
// Run explicitly with node scripts/test-portable.mjs --research.
import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { parse } from '@babel/parser';
import { inspectJavaScript } from '../dist/javascript.js';

// Exercise the recorder's actual predicate functions without running its batch.
// A permissive call match, missing binding check or missing command check must fail.
const root=resolve(import.meta.dirname,'..');
const endpoint='/api/owned/predicate-control';
const work=join(root,'scratch/containers-predicate-fix',new Date().toISOString().replace(/[:.]/g,'-'));
const sha=b=>createHash('sha256').update(b).digest('hex');
const cases=[
 ['selected','export function register(router) { router.post("/api/owned/predicate-control", 17); }',true],
 ['wrong-callee','export function register(router) { console.log("/api/owned/predicate-control"); }',false],
 ['wrong-index','export function register(router) { router.post("/api/other", "/api/owned/predicate-control"); }',false],
 ['wrong-function','function register(router) { router.post("/api/owned/predicate-control", 17); } export function other() {}',false],
 ['wrong-binding','export function register(router) { { const router = {}; router.post("/api/owned/predicate-control", 17); } }',false],
 ['renamed-parameter','export function register(renamed) { renamed.post("/api/owned/predicate-control", 17); }',true],
];
let predicates;
const observed=new Map();
before(()=>{
 mkdirSync(work,{recursive:true});
 const code=readFileSync(join(root,'scripts/qualify-containers.mjs'),'utf8');
 const ast=parse(code,{sourceType:'module'});
 const imports=ast.program.body.filter(n=>n.type==='ImportDeclaration'&&n.source.value.includes('container-predicates'))
  .map(n=>code.slice(n.start,n.source.start)+JSON.stringify(pathToFileURL(resolve(root,'scripts',n.source.value)).href)+code.slice(n.source.end,n.end));
 const functions=ast.program.body.filter(n=>n.type==='FunctionDeclaration'&&['factsHave','reaSelected'].includes(n.id.name)).map(n=>'export '+code.slice(n.start,n.end));
 writeFileSync(join(work,'recorder-predicates.mjs'),"import {readFileSync} from 'node:fs'; const json=r=>JSON.parse(readFileSync(r.stdout.path,'utf8'));\n"+imports.join('\n')+'\n'+functions.join('\n'));
 for(const [name,source] of cases){
  const app=join(work,name),temp=join(work,'temp');mkdirSync(app);mkdirSync(temp,{recursive:true});
  const sourcePath=join(app,'index.mjs');writeFileSync(sourcePath,source);
  const executable=join(root,'.runtime/node-v24.22.1-win-x64/node.exe');
  const args=[join(root,'research/rea/scripts/rea.mjs'),'analyze-javascript-application',app,'--format','json'];
  const started=Date.now(),run=spawnSync(executable,args,{cwd:root,env:{...process.env,TEMP:temp,TMP:temp},windowsHide:true,timeout:60000,maxBuffer:32*1024*1024});
  const streams={};for(const kind of ['stdout','stderr']){const bytes=run[kind]??Buffer.alloc(0),path=join(work,name+'.'+kind);writeFileSync(path,bytes);streams[kind]={path,bytes:bytes.length,sha256:sha(bytes)};}
  assert.equal(run.status,0,name+' source REA must actually succeed');
  const command={id:name,executable,args,cwd:root,exit_code:run.status,signal:run.signal,timed_out:!!run.error,wall_ms:Date.now()-started,...streams};
  const anti=inspectJavaScript(Buffer.from(source),{entryExport:'register',assumeStandardIntrinsics:true});
  writeFileSync(join(work,name+'.anti.json'),JSON.stringify(anti,null,2));
  observed.set(name,{source,sourcePath,command,anti});
 }
 writeFileSync(join(work,'evidence.json'),JSON.stringify({target_executed:false,orchestration_node:process.version,controls:[...observed].map(([name,x])=>({name,source_sha256:sha(Buffer.from(x.source)),source_path:x.sourcePath,command:x.command,anti_path:join(work,name+'.anti.json')}))},null,2));
});
before(async()=>{predicates=await import(pathToFileURL(join(work,'recorder-predicates.mjs')).href);});

for(const [name,,want]of cases){
 test('Anti binds selected call: '+name,()=>{const x=observed.get(name);assert.equal(predicates.factsHave(x.anti,endpoint,Buffer.from(x.source)),want);});
 test('REA binds selected call: '+name,()=>{const x=observed.get(name);assert.equal(predicates.reaSelected(x.command,endpoint,x.sourcePath).selected_assertion,want);});
}
test('Anti refuses a fact from different source bytes',()=>{const x=observed.get('selected');assert.equal(predicates.factsHave(x.anti,endpoint,Buffer.from(x.source+'\n')),false);});
test('REA requires actual successful command exit',()=>{const x=observed.get('selected');assert.equal(predicates.reaSelected({...x.command,exit_code:1},endpoint,x.sourcePath).selected_assertion,false);});
test('REA rejects timed out command despite retained matching stdout',()=>{const x=observed.get('selected');assert.equal(predicates.reaSelected({...x.command,timed_out:true},endpoint,x.sourcePath).selected_assertion,false);});
test('REA rejects stdout not bound to its retained digest',()=>{const x=observed.get('selected');assert.equal(predicates.reaSelected({...x.command,stdout:{...x.command.stdout,sha256:'0'.repeat(64)}},endpoint,x.sourcePath).selected_assertion,false);});
test('REA rejects source from another command input path',()=>{const x=observed.get('selected'),other=observed.get('renamed-parameter');assert.equal(predicates.reaSelected(x.command,endpoint,other.sourcePath).selected_assertion,false);});
