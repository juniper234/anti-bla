// Research suite (5 tests): requires retained private report/raw-evidence paths.
// Run explicitly with node scripts/test-portable.mjs --research.
import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
const traverse=traverseModule.default??traverseModule;
const root=resolve(import.meta.dirname,'..');
const original=JSON.parse(readFileSync(join(root,'reports/C6-containers-2026-10-30T03-26-09-988Z.json')));
const selected=()=>structuredClone(original.records.find(r=>r.family==='html'));
let auditRow;
before(async()=>{
 const file=join(root,'test/helpers/container-audit.mjs'),code=readFileSync(file,'utf8'),ast=parse(code,{sourceType:'module'});
 let block;traverse(ast,{IfStatement(p){const text=code.slice(p.node.test.start,p.node.test.end);if(text==="['html','directory'].includes(row.family)"){block=code.slice(p.node.start,p.node.end);p.stop();}}});
 assert.ok(block,'actual auditor must contain its selected JS row branch');
 const imports=ast.program.body.filter(n=>n.type==='ImportDeclaration'&&n.source.value.includes('container-predicates'))
  .map(n=>code.slice(n.start,n.source.start)+JSON.stringify(pathToFileURL(resolve(root,'test/helpers',n.source.value)).href)+code.slice(n.source.end,n.end));
 const dir=join(root,'scratch/containers-audit-predicate-tests',new Date().toISOString().replace(/[:.]/g,'-'));mkdirSync(dir,{recursive:true});
 const path=join(dir,'actual-audit-branch.mjs');
 writeFileSync(path,imports.join('\n')+'\nexport function auditRow(row,commands){const r={commands},base={},errors=[];function check(c,m){if(!c)errors.push(m);return !!c;}\n'+block+'\nreturn {base,errors};}');
 ({auditRow}=await import(pathToFileURL(path).href));
});

// These controls catch accepting a remembered success flag after raw evidence
// changes, and rejecting genuine raw evidence only because a flag was changed.
test('audit accepts retained raw task evidence despite false stored flags',()=>{
 const row=selected();row.rea_assertions.clean.selected_assertion=false;row.rea_assertions.handoff.selected_assertion=false;row.assertions.anti_selected_task=false;
 assert.deepEqual(auditRow(row,original.commands).errors,[]);
});
test('audit rejects wrong raw Anti fact despite true stored flags',()=>{
 const row=selected();row.anti.facts=row.anti.facts.filter(f=>f.kind!=='call-argument');
 assert.ok(auditRow(row,original.commands).errors.length>0);
});
test('audit rejects missing raw REA task despite true stored flags',()=>{
 const row=selected();row.expected='/api/never-present-in-raw-evidence';
 assert.ok(auditRow(row,original.commands).errors.length>0);
});
test('audit rejects actual command failure with a successful stored row ref',()=>{
 const row=selected(),commands=structuredClone(original.commands);commands.find(c=>c.id===row.handoff.command_id).exit_code=1;
 assert.ok(auditRow(row,commands).errors.length>0);
});
test('audit rejects unbound raw stdout despite true stored flags',()=>{
 const row=selected(),commands=structuredClone(original.commands);commands.find(c=>c.id===row.handoff.command_id).stdout.sha256='0'.repeat(64);
 assert.ok(auditRow(row,commands).errors.length>0);
});
